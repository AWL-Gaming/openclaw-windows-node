$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Replace-Once([string]$Path, [string]$Old, [string]$New) {
    $text = [System.IO.File]::ReadAllText($Path)
    if (-not $text.Contains($Old)) {
        throw "Anchor not found in $Path"
    }
    $text = $text.Replace($Old, $New)
    [System.IO.File]::WriteAllText($Path, $text, [System.Text.UTF8Encoding]::new($false))
}

$bridge = Join-Path $repo 'src\OpenClaw.Shared\Mcp\McpToolBridge.cs'
$bridgeInsert = @'
        // files.upload.* - local MCP-only, bounded writes beneath Documents\SE\GPT.
        ["files.upload.begin"] =
            "Begin a bounded binary upload beneath the approved Documents\\SE\\GPT root. Args: relativePath (string, required), expectedSize (integer 1..67108864, required), expectedSha256 (64 hexadecimal characters, required), overwrite (bool, default false). Returns { uploadId, relativePath, expectedSize, maxChunkBase64Chars, expiresAt }.",
        ["files.upload.append"] =
            "Append one independently base64-encoded byte chunk to an active upload. Args: uploadId (string, required), sequence (zero-based integer, required), base64Chunk (string, required, max 500000 characters). Returns { uploadId, acceptedSequence, nextSequence, bytesReceived, expectedSize, complete }.",
        ["files.upload.commit"] =
            "Verify expected size and SHA-256, then atomically publish the staged upload. Args: uploadId (string, required). Returns { uploadId, path, uncPath, relativePath, sizeBytes, sha256 }.",
        ["files.upload.abort"] =
            "Abort an active upload and delete its staged bytes. Args: uploadId (string, required). Returns { uploadId, aborted, alreadyMissing }.",

        // canvas.*
'@
Replace-Once $bridge '        // canvas.*' $bridgeInsert.TrimEnd()

$skill = Join-Path $repo 'src\OpenClaw.WinNode.Cli\skill.md'
$skillInsert = @'
## File upload (files.upload.*)

These commands are local-MCP-only and can write only beneath
`%USERPROFILE%\Documents\SE\GPT`. Upload chunks must be independently base64
encoded. The final file is published only after size and SHA-256 verification.

### files.upload.begin
```json
{
  "relativePath": "batch\\ORIGINALS\\01-original.png",
  "expectedSize": 2744717,
  "expectedSha256": "64 lowercase or uppercase hexadecimal characters",
  "overwrite": false
}
```
Returns `{ uploadId, relativePath, expectedSize, maxChunkBase64Chars, expiresAt }`.
The default maximum file size is 64 MiB.

### files.upload.append
```json
{
  "uploadId": "id returned by files.upload.begin",
  "sequence": 0,
  "base64Chunk": "one independently encoded chunk, at most 500000 characters"
}
```
Call repeatedly with strictly increasing zero-based sequence numbers. Returns
`{ uploadId, acceptedSequence, nextSequence, bytesReceived, expectedSize, complete }`.

### files.upload.commit
```json
{"uploadId": "id returned by files.upload.begin"}
```
Requires the exact expected byte count and SHA-256. Atomically publishes the
file and returns `{ uploadId, path, uncPath, relativePath, sizeBytes, sha256 }`.

### files.upload.abort
```json
{"uploadId": "id returned by files.upload.begin"}
```
Deletes staged bytes and returns `{ uploadId, aborted, alreadyMissing }`.

### canvas.present
'@
Replace-Once $skill '### canvas.present' $skillInsert.TrimEnd()

$drift = Join-Path $repo 'tests\OpenClaw.WinNode.Cli.Tests\SkillMdDriftTests.cs'
$driftOld = '            new DeviceCapability(NullLogger.Instance, provider),'
$driftNew = @'
            new DeviceCapability(NullLogger.Instance, provider),
            new FileUploadCapability(
                NullLogger.Instance,
                Path.Combine(Path.GetTempPath(), "openclaw-skill-drift")),
'@
Replace-Once $drift $driftOld $driftNew.TrimEnd()

$testing = Join-Path $repo 'docs\WINDOWS_NODE_TESTING.md'
$testingOld = '- `system` - Notifications, command execution (`system.run`, `system.run.prepare`, `system.which`), exec approval policy'
$testingNew = @'
- `system` - Notifications, command execution (`system.run`, `system.run.prepare`, `system.which`), exec approval policy
- `files` - Local-MCP-only bounded chunked uploads into `%USERPROFILE%\Documents\SE\GPT` (`files.upload.begin`, `files.upload.append`, `files.upload.commit`, `files.upload.abort`)
'@
Replace-Once $testing $testingOld $testingNew.TrimEnd()

$mcp = Join-Path $repo 'docs\MCP_MODE.md'
$mcpOld = '1. **Per-tool input schemas.** Add an `IReadOnlyDictionary<string, JsonElement> InputSchemas`'
$mcpNew = @'
1. **Per-tool input schemas.** Add an `IReadOnlyDictionary<string, JsonElement> InputSchemas`

The local MCP surface also includes `files.upload.begin`, `files.upload.append`,
`files.upload.commit`, and `files.upload.abort`. These commands accept bounded,
independently base64-encoded chunks and publish files only beneath
`%USERPROFILE%\Documents\SE\GPT` after exact size and SHA-256 verification.
'@
Replace-Once $mcp $mcpOld $mcpNew.TrimEnd()

Write-Output 'Applied file-upload metadata and documentation updates.'
