/**
 * Backfill per-column encrypted PHI for legacy patient rows.
 * Run: npx tsx scripts/backfill-patient-phi-columns.ts
 */
import "dotenv/config";
import { storage } from "../server/storage.js";

async function main() {
  const result = await storage.backfillAllPatientPhiColumns();
  console.log(
    `Patient PHI column backfill complete: updated=${result.updated} skipped=${result.skipped}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
