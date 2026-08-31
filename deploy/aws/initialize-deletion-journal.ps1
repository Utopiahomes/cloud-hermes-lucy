param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]{3,255}$')]
    [string]$HeadTableName,
    [Parameter(Mandatory = $true)][guid]$JournalId,
    [Parameter(Mandatory = $true)][guid]$RegistryId,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z]{2}(-gov)?-[a-z]+-\d$')]
    [string]$AwsRegion
)

$journalSetupItem = @{
    journal_key = @{ S = 'HEAD' }
    journal_id = @{ S = $JournalId.ToString() }
    registry_id = @{ S = $RegistryId.ToString() }
    sequence = @{ N = '0' }
    digest = @{ S = ('0' * 64) }
} | ConvertTo-Json -Compress -Depth 4

# Run once with the human security-administrator identity. The condition makes
# rerunning safe only when the head is absent; never overwrite/rewind a journal.
& aws dynamodb put-item `
    --region $AwsRegion `
    --table-name $HeadTableName `
    --condition-expression 'attribute_not_exists(journal_key)' `
    --item $journalSetupItem
if ($LASTEXITCODE -ne 0) {
    throw 'Journal initialization failed; inspect the existing head without modifying it.'
}
Write-Output "Deletion journal initialized at sequence 0. Record the two UUIDs as metadata, not secrets."
