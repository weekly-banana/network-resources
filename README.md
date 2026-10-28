# Network resources

Public signed address directory for Shepot native clients.

Current image endpoint (Android 0.4.5, macOS 0.1.5, Windows 1.0.5 and later):

https://raw.githubusercontent.com/weekly-banana/network-resources/main/assets/network.png

JSON endpoint for earlier clients:

https://raw.githubusercontent.com/weekly-banana/network-resources/main/assets/route-index.json

Both contain the same P-256-signed public API hostnames. No subscription keys, device identities, account data or private signing keys are published.

## Automatic updates

Refresh signed directory checks the operator's public signed sources approximately every 15 minutes. GitHub can delay scheduled runs. A verified newer directory updates both endpoints; their URLs stay the same. Errors preserve the last published valid files. Manual checks are available in Actions.

A public verification status is committed once per week to keep the repository active. If GitHub disables Actions or the owner account, an operator must restore automation. The last published files remain available.

To change domain names, update and sign a higher directory version on the existing operator backend. Do not edit the image or JSON by hand. No personal access token or backend credentials are required by the workflow; it uses the short-lived repository-scoped GITHUB_TOKEN.

## Image format

The image is a lossless RGB8 PNG with no interlacing. After standard PNG decompression and row unfiltering, each R, G and B channel contributes its least significant bit in row-major order. Bits are packed most significant first into bytes: ASCII SHPTRGB1, a four-byte big-endian JSON length, then the signed UTF-8 JSON.

The strict decoder accepts only IHDR, consecutive IDAT chunks and IEND; it verifies CRCs and zlib checksums. Limits are 512 by 512 pixels, 256 KiB of PNG and 32 KiB of extracted JSON. The extracted directory still requires the existing P-256 signature and rollback checks. This envelope is not encryption and does not guarantee protection from domain blocking or traffic inspection.

Mirror the original PNG bytes. Resizing, conversion to JPEG, color conversion or image optimization can destroy the hidden data. The encoder and verifier are in tools/directory_png.py; tools/sync_directory.py publishes both formats.
