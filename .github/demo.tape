# VHS Demo — living-off-the-land-lolbins-mcp-server
Output .github/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 600
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 30ms

# Show help
Type `npx -y living-off-the-land-lolbins-mcp-server --help`
Sleep 300ms
Enter
Sleep 6s

# Lookup a LOL binary
Type `npx -y living-off-the-land-lolbins-mcp-server --tool lookup_binary '{"binary":"certutil"}'`
Sleep 300ms
Enter
Sleep 6s

# Search for reverse shell techniques
Type `npx -y living-off-the-land-lolbins-mcp-server --tool search_techniques '{"mode":"function","function":"reverse_shell"}'`
Sleep 300ms
Enter
Sleep 6s

# Check KB stats
Type `npx -y living-off-the-land-lolbins-mcp-server --tool update_knowledge_base '{"mode":"stats"}'`
Sleep 300ms
Enter
Sleep 6s

Sleep 2s
