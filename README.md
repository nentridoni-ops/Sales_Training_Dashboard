# Sales Training Dashboard — Vercel migration test

## What changed
- Google Apps Script sync calls were removed from the frontend.
- Cloud endpoint is now `/api/state`.
- Shared dashboard state is stored in Vercel Blob.
- The existing dashboard calculation/category/training/incentive logic is retained.
- The old manual Google Drive/Apps Script sync is no longer required for the new path.

## Required once in Vercel
Connect a Vercel Blob store to the project so `BLOB_READ_WRITE_TOKEN` is available to the serverless function.
No Google Apps Script is required after that.

## Test
1. Deploy this folder to the existing Vercel project.
2. Open the production URL on MacBook.
3. Upload `salespersonwise`, save it, and wait for the cloud status to say it is saved.
4. Open the same URL on the phone.
5. The phone should load the same state from `/api/state`.
6. Change Staff Master on one device and verify the other device after refresh.

## Important security note
The test API currently uses a public shared state endpoint. Before using it for sensitive production data, add authentication/authorization (for example Vercel Authentication or a proper team login) so arbitrary visitors cannot overwrite the state.
