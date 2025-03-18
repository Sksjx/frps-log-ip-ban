$allRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "ban ip *" }
Write-Output "Total ban ip rules found: $($allRules.Count)"

$thresholdDate = (Get-Date).AddDays(-30)
Write-Output "Threshold date for rule expiration: $thresholdDate"

$filePath = "C:\Users\Administrator\Desktop\frps-log-ip-ban-main\banip.txt"
$ipAddresses = Get-Content $filePath | ForEach-Object {
    if ($_ -match "^\s*(\d{1,3}(\.\d{1,3}){3})\s*(\d{4}-\d{2}-\d{2})") {
        [PSCustomObject]@{
            IP   = $matches[1]
            Date = [datetime]::ParseExact($matches[3], "yyyy-MM-dd", $null)
        }
    }
} | Group-Object IP | ForEach-Object { $_.Group | Select-Object -First 1 }  # Eliminate duplicates from the input file
Write-Output "IPs and dates loaded from file: $($ipAddresses.Count)"

foreach ($ip in $ipAddresses) {
    Write-Output "Checking rules for IP: $($ip.IP) with date: $($ip.Date)"
    if ($ip.Date -lt $thresholdDate) {
        $ruleName = "ban ip $($ip.IP)"
        $rule = $allRules | Where-Object { $_.DisplayName -eq $ruleName }
        if ($rule) {
            Remove-NetFirewallRule -DisplayName $ruleName
            Write-Output "Removed expired rule for IP '$($ip.IP)' from $($ip.Date)."
        } else {
            Write-Output "No rule found to remove for IP '$($ip.IP)'."
        }
    }
}
foreach ($entry in $ipAddresses) {
    if (-not $entry.Date -or $entry.Date -ge $thresholdDate) {
        $ruleName = "ban ip $($entry.IP)"
        $existingRule = $allRules | Where-Object { $_.DisplayName -eq $ruleName }

        if (!$existingRule) {
            New-NetFirewallRule -DisplayName "$ruleName" -Direction Inbound -Action Block -RemoteAddress $entry.IP -Profile Any -Description $(if ($entry.Date) { $entry.Date.ToString("yyyy-MM-dd") } else { "" })
            Write-Output "Added new rule for IP '$($entry.IP)'."
        } else {
            $daysLeft = ($entry.Date.AddDays(30) - (Get-Date)).Days
            if ($daysLeft -gt 0) {
                Write-Output "Rule '$ruleName' already exists. Only $daysLeft days left until release."
            } elseif ($daysLeft -eq 0) {
                Write-Output "Rule '$ruleName' already exists. It will expire today."
            } else {
                Write-Output "Rule '$ruleName' already exists and is set to expire in $(-$daysLeft) days."
            }
        }
    }
}
