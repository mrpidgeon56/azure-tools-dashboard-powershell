@{
    # PSScriptAnalyzer configuration shared by CI (.github/scripts/Run-Lint.ps1) and local runs.
    #
    # Severity gating lives in Run-Lint.ps1, not here: Error-severity findings and any
    # security-rule findings BLOCK the build; Warning/Information are reported only.
    IncludeDefaultRules = $true
    Severity            = @('Error', 'Warning', 'Information')

    # Deliberate patterns in this codebase, excluded to keep the lint signal meaningful.
    # (Both are non-blocking Warnings regardless — excluded only to cut noise.)
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'                  # scanners stream live progress to the console by design
        'PSUseUsingScopeModifierInNewRunspaces'  # ForEach-Object -Parallel re-injects helpers via $funcDefs by design
    )
}
