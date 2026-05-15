import { useState, useEffect, useCallback, useRef } from 'react';
import { Room, RoomEvent, Track, RemoteParticipant, LocalParticipant } from 'livekit-client';
import { useToast } from '@/hooks/use-toast';

/**
 * livekit-client builds signal URLs as {host}/rtc/... If the server already returns a URL
 * ending in /rtc, the WebSocket becomes /rtc/rtc/v1 and the handshake returns 404.
 */
function normalizeLiveKitServerUrl(url: string | undefined): string {
  if (url == null || typeof url !== 'string') return '';
  let u = url.trim().replace(/\/+$/, '');
  while (/\/rtc$/i.test(u)) {
    u = u.replace(/\/rtc$/i, '').replace(/\/+$/, '');
  }
  return u;
}

export interface LiveKitRoomConfig {
  roomName: string;
  participantName: string;
  participantRole?: string;
  url?: string;
  token?: string;
  audioEnabled?: boolean;
  videoEnabled?: boolean;
}

export interface UseLiveKitRoomReturn {
  room: Room | null;
  isConnected: boolean;
  isConnecting: boolean;
  error: string | null;
  localParticipant: LocalParticipant | null;
  remoteParticipants: RemoteParticipant[];
  connect: (config: LiveKitRoomConfig) => Promise<void>;
  disconnect: () => void;
  toggleAudio: () => void;
  toggleVideo: () => void;
  isAudioEnabled: boolean;
  isVideoEnabled: boolean;
}

export function useLiveKitRoom(): UseLiveKitRoomReturn {
  const [room, setRoom] = useState<Room | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [localParticipant, setLocalParticipant] = useState<LocalParticipant | null>(null);
  const [remoteParticipants, setRemoteParticipants] = useState<RemoteParticipant[]>([]);
  const [isAudioEnabled, setIsAudioEnabled] = useState(true);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const roomRef = useRef<Room | null>(null);
  const localParticipantInfoRef = useRef<{ name: string; role?: string } | null>(null);
  const remoteParticipantsInfoRef = useRef<Map<string, { name: string; role?: string }>>(new Map());
  const { toast } = useToast();

  const connect = useCallback(async (config: LiveKitRoomConfig) => {
    if (isConnecting || isConnected) {
      console.warn('Already connecting or connected');
      return;
    }

    setIsConnecting(true);
    setError(null);

    try {
      // Fetch token if not provided
      let token = config.token;
      if (!token) {
        const response = await fetch('/api/livekit/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
            'X-Tenant-Subdomain': window.location.hostname.split('.')[0] || 'demo',
          },
          body: JSON.stringify({
            roomName: config.roomName,
            participantName: config.participantName,
          }),
        });

        if (!response.ok) {
          throw new Error('Failed to get LiveKit token');
        }

        const data = await response.json();
        token = data.token;
        config.url = data.url;
      }

      const serverUrl = normalizeLiveKitServerUrl(config.url);
      if (!serverUrl) {
        throw new Error('LiveKit URL is required');
      }

      if (!token) {
        throw new Error('LiveKit token is required');
      }

      // Create and connect to room
      const newRoom = new Room({
        adaptiveStream: true,
        dynacast: true,
        videoCaptureDefaults: {
          resolution: { width: 1280, height: 720 },
        },
      });

      // Store local participant info
      localParticipantInfoRef.current = {
        name: config.participantName,
        role: config.participantRole,
      };

      // Set up event listeners
      newRoom.on(RoomEvent.Connected, () => {
        console.log('✅ Connected to LiveKit room');
        setIsConnected(true);
        setIsConnecting(false);
        setLocalParticipant(newRoom.localParticipant);
        setRemoteParticipants(Array.from(newRoom.remoteParticipants.values()));
        toast({
          title: 'Connected',
          description: 'Successfully connected to the call',
        });
      });

      newRoom.on(RoomEvent.Disconnected, async (reason) => {
        console.log('❌ Disconnected from LiveKit room:', reason);
        
        // Explicitly stop all local tracks to ensure camera/mic are released
        try {
          const localPart = newRoom.localParticipant;
          if (localPart) {
            // Stop all published tracks
            const publications = Array.from(localPart.trackPublications.values());
            for (const pub of publications) {
              if (pub.track) {
                try {
                  pub.track.stop();
                  console.log('🛑 Stopped track on disconnect:', pub.track.kind);
                } catch (e) {
                  console.log('Error stopping track on disconnect:', e);
                }
              }
            }
          }
        } catch (e) {
          console.log('Error cleaning up tracks on disconnect:', e);
        }
        
        // Also stop any remaining media streams directly
        try {
          const mediaDevices = navigator.mediaDevices;
          if (mediaDevices && typeof mediaDevices.enumerateDevices === 'function') {
            // Get all media streams and stop them
            const videoElements = document.querySelectorAll('video');
            videoElements.forEach((video) => {
              if (video.srcObject instanceof MediaStream) {
                video.srcObject.getTracks().forEach((track) => {
                  track.stop();
                  console.log('🛑 Stopped media stream track:', track.kind);
                });
                video.srcObject = null;
              }
            });
          }
        } catch (e) {
          console.log('Error stopping media streams on disconnect:', e);
        }
        
        // Get the local participant's identity before clearing state
        const localParticipantIdentity = newRoom.localParticipant?.identity;
        let disconnectedParticipantName = '';
        let disconnectedParticipantRole: string | undefined;
        
        // Try to extract name and role from local participant identity
        if (localParticipantIdentity) {
          const identityParts = localParticipantIdentity.split(':');
          if (identityParts.length >= 5) {
            disconnectedParticipantRole = identityParts[0];
            const firstName = identityParts[2];
            const lastName = identityParts[3];
            if (firstName && lastName) {
              disconnectedParticipantName = `${firstName} ${lastName}`;
            }
          } else {
            // Fallback to stored local info
            const localInfo = localParticipantInfoRef.current;
            if (localInfo) {
              disconnectedParticipantName = localInfo.name;
              disconnectedParticipantRole = localInfo.role;
            } else {
              disconnectedParticipantName = localParticipantIdentity;
            }
          }
        } else {
          // Fallback to stored local info if identity is not available
          const localInfo = localParticipantInfoRef.current;
          if (localInfo) {
            disconnectedParticipantName = localInfo.name;
            disconnectedParticipantRole = localInfo.role;
          }
        }
        
        setIsConnected(false);
        setIsConnecting(false);
        setLocalParticipant(null);
        setRemoteParticipants([]);
        
        // Don't show toast here - parent components handle showing modals
        // Clear stored participant info
        localParticipantInfoRef.current = null;
        remoteParticipantsInfoRef.current.clear();
      });

      newRoom.on(RoomEvent.ParticipantConnected, (participant) => {
        console.log('👤 Participant connected:', participant.identity);
        setRemoteParticipants(Array.from(newRoom.remoteParticipants.values()));
        
        // Try to extract name and role from participant identity or metadata
        // The identity format is typically: "role:id:firstName:lastName:email"
        const identityParts = participant.identity?.split(':') || [];
        let participantName = participant.name || participant.identity || 'Unknown';
        let participantRole: string | undefined;
        
        if (identityParts.length >= 5) {
          participantRole = identityParts[0];
          const firstName = identityParts[2];
          const lastName = identityParts[3];
          if (firstName && lastName) {
            participantName = `${firstName} ${lastName}`;
          }
        } else if (participant.name) {
          participantName = participant.name;
        }
        
        // Store remote participant info
        remoteParticipantsInfoRef.current.set(participant.identity, {
          name: participantName,
          role: participantRole,
        });
      });

      newRoom.on(RoomEvent.ParticipantDisconnected, (participant) => {
        console.log('👤 Participant disconnected:', participant.identity);
        setRemoteParticipants(Array.from(newRoom.remoteParticipants.values()));
        
        // Don't show toast here - LiveKit components handle this and call onDisconnect()
        // which triggers the modal in parent components
        
        // Remove from stored participants
        remoteParticipantsInfoRef.current.delete(participant.identity);
      });

      newRoom.on(RoomEvent.TrackSubscribed, (track, publication, participant) => {
        console.log('📹 Track subscribed:', track.kind, participant.identity);
        // Update remote participants list when tracks are subscribed
        if (!participant.isLocal) {
          setRemoteParticipants(Array.from(newRoom.remoteParticipants.values()));
        }
      });

      newRoom.on(RoomEvent.TrackUnsubscribed, (track, publication, participant) => {
        console.log('📹 Track unsubscribed:', track.kind, participant.identity);
      });

      newRoom.on(RoomEvent.TrackMuted, (publication, participant) => {
        console.log('🔇 Track muted:', publication.kind, participant.identity);
      });

      newRoom.on(RoomEvent.TrackUnmuted, (publication, participant) => {
        console.log('🔊 Track unmuted:', publication.kind, participant.identity);
      });

      newRoom.on(RoomEvent.LocalTrackPublished, (publication, participant) => {
        console.log('📤 Local track published:', publication.kind);
      });

      newRoom.on(RoomEvent.LocalTrackUnpublished, (publication, participant) => {
        console.log('📤 Local track unpublished:', publication.kind);
      });

      newRoom.on(RoomEvent.RoomMetadataChanged, (metadata) => {
        console.log('📝 Room metadata changed:', metadata);
      });

      // Connect to room
      await newRoom.connect(serverUrl, token);

      // Request permissions first, then enable tracks
      // This prevents "device not found" errors
      if (config.audioEnabled !== false || config.videoEnabled !== false) {
        try {
          // Request permissions by getting a temporary stream
          const constraints: MediaStreamConstraints = {};
          if (config.audioEnabled !== false) {
            constraints.audio = true;
          }
          if (config.videoEnabled !== false) {
            constraints.video = { width: 1280, height: 720 };
          }

          // Request permissions first
          const tempStream = await navigator.mediaDevices.getUserMedia(constraints);
          // Stop the temporary stream immediately - we just needed permissions
          tempStream.getTracks().forEach(track => track.stop());
          console.log('✅ Media permissions granted');
        } catch (err: any) {
          console.error('❌ Failed to get media permissions:', err);
          // Continue anyway - user can enable manually later
          if (config.audioEnabled !== false) {
            setIsAudioEnabled(false);
          }
          if (config.videoEnabled !== false) {
            setIsVideoEnabled(false);
          }
          
          // Provide more specific error messages
          let errorMessage = 'Could not access media devices. You can join and enable them manually.';
          if (err.name === 'NotAllowedError') {
            errorMessage = 'Please allow camera/microphone access to join the call with video/audio.';
          } else if (err.name === 'NotFoundError' || err.message?.includes('not found') || err.message?.includes('device not found')) {
            errorMessage = 'No camera/microphone device found. The call will continue without video/audio.';
          }
          
          toast({
            title: 'Media Permissions',
            description: errorMessage,
            variant: 'default',
          });
        }
      }

      // Now enable tracks (permissions should be granted)
      if (config.audioEnabled !== false) {
        try {
          await newRoom.localParticipant.setMicrophoneEnabled(true);
          console.log('✅ Microphone enabled');
        } catch (err: any) {
          console.error('❌ Failed to enable microphone:', err);
          setIsAudioEnabled(false);
          // Don't throw - allow call to continue without audio
        }
      }

      if (config.videoEnabled !== false) {
        try {
          // Check if camera is available before trying to enable it
          let hasCamera = false;
          try {
            const devices = await navigator.mediaDevices.enumerateDevices();
            hasCamera = devices.some(device => device.kind === 'videoinput' && device.deviceId !== '');
            
            // If no camera found in initial enumeration, try requesting permission
            if (!hasCamera) {
              try {
                const tempStream = await navigator.mediaDevices.getUserMedia({ video: true });
                tempStream.getTracks().forEach(track => track.stop());
                // Re-enumerate after permission
                const devicesAfterPerm = await navigator.mediaDevices.enumerateDevices();
                hasCamera = devicesAfterPerm.some(device => device.kind === 'videoinput' && device.deviceId !== '');
              } catch (permErr: any) {
                // Permission denied or no camera - that's okay, we'll continue without video
                console.log('⚠️ Camera not available or permission denied:', permErr.name);
                hasCamera = false;
              }
            }
          } catch (enumErr) {
            console.warn('⚠️ Could not enumerate devices:', enumErr);
            hasCamera = false;
          }

          if (hasCamera) {
            await newRoom.localParticipant.setCameraEnabled(true);
            console.log('✅ Camera enabled');
          } else {
            console.log('⚠️ No camera device found - continuing call without video');
            setIsVideoEnabled(false);
            toast({
              title: 'Camera Not Available',
              description: 'No camera device found. The call will continue without video.',
              variant: 'default',
            });
          }
        } catch (err: any) {
          console.error('❌ Failed to enable camera:', err);
          setIsVideoEnabled(false);
          // Don't throw - allow call to continue without video
          if (err.name === 'NotFoundError' || err.message?.includes('not found') || err.message?.includes('device not found')) {
            toast({
              title: 'Camera Not Available',
              description: 'No camera device found. The call will continue without video.',
              variant: 'default',
            });
          }
        }
      }

      setRoom(newRoom);
      roomRef.current = newRoom;
    } catch (err: any) {
      console.error('❌ Failed to connect to LiveKit room:', err);
      setError(err.message || 'Failed to connect to room');
      setIsConnecting(false);
      toast({
        title: 'Connection Failed',
        description: err.message || 'Failed to connect to the call',
        variant: 'destructive',
      });
    }
  }, [isConnecting, isConnected, toast]);

  const disconnect = useCallback(async () => {
    if (roomRef.current) {
      try {
        // Explicitly stop local tracks before disconnecting
        const localParticipant = roomRef.current.localParticipant;
        if (localParticipant) {
          // Disable camera and microphone first
          try {
            await localParticipant.setCameraEnabled(false);
            console.log('📷 Camera disabled');
          } catch (e) {
            console.log('Could not disable camera:', e);
          }
          try {
            await localParticipant.setMicrophoneEnabled(false);
            console.log('🎤 Microphone disabled');
          } catch (e) {
            console.log('Could not disable microphone:', e);
          }
          
          // Unpublish all tracks
          const publications = Array.from(localParticipant.trackPublications.values());
          for (const publication of publications) {
            if (publication.track) {
              try {
                await localParticipant.unpublishTrack(publication.track);
                publication.track.stop();
                console.log('🛑 Stopped and unpublished track:', publication.track.kind);
              } catch (e) {
                console.log('Error unpublishing track:', e);
              }
            }
          }
        }
      } catch (e) {
        console.log('Error during track cleanup:', e);
      }
      
      // Now disconnect from the room (only if room exists)
      if (roomRef.current) {
        try {
      roomRef.current.disconnect();
        } catch (e) {
          console.log('Error disconnecting from room:', e);
        }
      }
      roomRef.current = null;
      setRoom(null);
      setIsConnected(false);
      setIsAudioEnabled(false);
      setIsVideoEnabled(false);
      setLocalParticipant(null);
      setRemoteParticipants([]);
      console.log('🔌 Fully disconnected from room');
    }
  }, []);

  const toggleAudio = useCallback(async () => {
    if (!room) return;

    try {
      const enabled = !isAudioEnabled;

      if (enabled) {
        // Check if microphone is available before enabling
        try {
          const devices = await navigator.mediaDevices.enumerateDevices();
          const hasMicrophone = devices.some(device => device.kind === 'audioinput');

          if (!hasMicrophone) {
            throw new Error('No microphone device found');
          }

          // Request permission if needed
          const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
          stream.getTracks().forEach(track => track.stop()); // Stop temp stream
        } catch (permErr: any) {
          if (permErr.name === 'NotAllowedError' || permErr.name === 'NotFoundError') {
            throw new Error('Microphone access denied or not available');
          }
          throw permErr;
        }
      }

      await room.localParticipant.setMicrophoneEnabled(enabled);
      setIsAudioEnabled(enabled);
    } catch (err: any) {
      console.error('Failed to toggle audio:', err);
      const errorMessage = err.message || 'Failed to toggle microphone';
      toast({
        title: 'Microphone Error',
        description: errorMessage.includes('denied') || errorMessage.includes('not available')
          ? 'Please allow microphone access in your browser settings'
          : errorMessage,
        variant: 'destructive',
      });
    }
  }, [room, isAudioEnabled, toast]);

  const toggleVideo = useCallback(async () => {
    if (!room) return;

    const enabled = !isVideoEnabled;

    try {
      if (enabled) {
        // First, check if camera devices are available
        let devices: MediaDeviceInfo[] = [];
        try {
          devices = await navigator.mediaDevices.enumerateDevices();
        } catch (enumErr) {
          console.warn('Could not enumerate devices:', enumErr);
        }

        const hasCamera = devices.some(device => device.kind === 'videoinput' && device.deviceId !== '');

        if (!hasCamera) {
          // Try requesting permission to get device list
          try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: true });
            stream.getTracks().forEach(track => track.stop());
            // Re-enumerate after permission
            devices = await navigator.mediaDevices.enumerateDevices();
            const hasCameraAfterPerm = devices.some(device => device.kind === 'videoinput' && device.deviceId !== '');
            if (!hasCameraAfterPerm) {
              throw new Error('No camera device found on your system');
            }
          } catch (permErr: any) {
            if (permErr.name === 'NotAllowedError') {
              throw new Error('Camera access denied. Please allow camera access in your browser settings.');
            } else if (permErr.name === 'NotFoundError' || permErr.message?.includes('not found')) {
              throw new Error('No camera device found. Please connect a camera and try again.');
            }
            throw permErr;
          }
        }
      }

      // Now try to enable/disable camera in LiveKit
      await room.localParticipant.setCameraEnabled(enabled);
      setIsVideoEnabled(enabled);

      if (enabled) {
        console.log('✅ Camera enabled successfully');
      } else {
        console.log('✅ Camera disabled');
      }
    } catch (err: any) {
      console.error('Failed to toggle video:', err);

      // Don't update state if operation failed
      // State will remain as it was

      let errorMessage = 'Failed to toggle camera';
      if (err.name === 'NotFoundError' || err.message?.includes('not found') || err.message?.includes('device not found')) {
        errorMessage = 'No camera device found. Please connect a camera and refresh the page.';
      } else if (err.name === 'NotAllowedError' || err.message?.includes('denied')) {
        errorMessage = 'Camera access denied. Please allow camera access in your browser settings and try again.';
      } else if (err.message) {
        errorMessage = err.message;
      }

      toast({
        title: 'Camera Error',
        description: errorMessage,
        variant: 'destructive',
      });
    }
  }, [room, isVideoEnabled, toast]);

  // Update audio/video state from room
  useEffect(() => {
    if (!room) return;

    const updateState = () => {
      const micEnabled = room.localParticipant.isMicrophoneEnabled;
      const camEnabled = room.localParticipant.isCameraEnabled;
      setIsAudioEnabled(micEnabled);
      setIsVideoEnabled(camEnabled);
    };

    updateState();
    const interval = setInterval(updateState, 1000);
    return () => clearInterval(interval);
  }, [room]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (roomRef.current) {
        roomRef.current.disconnect();
      }
    };
  }, []);

  return {
    room,
    isConnected,
    isConnecting,
    error,
    localParticipant,
    remoteParticipants,
    connect,
    disconnect,
    toggleAudio,
    toggleVideo,
    isAudioEnabled,
    isVideoEnabled,
  };
}

