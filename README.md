```markdown
### New: PSC (Permissions.PSC) generation

This action can now optionally generate a Permissions.PSC file (compatible with MagmaMCNet/PermissionManager) alongside the existing data.json output.

Usage
- Add the `psc` input to your workflow step and set it to `true`.

Example workflow snippet:
```yaml
- name: Track VRChat API
  uses: kyrillk/VrchatAPi@main
  with:
    output: 'output'
    username: ${{ secrets.VRCHAT_USERNAME }}
    password: ${{ secrets.VRCHAT_PASSWORD }}
    key: ${{ secrets.VRCHAT_2FA_KEY }}
    groups: 'grp_your-group-id'
    psc: 'true'
```

Behavior
- When enabled, the action will create `output/Permissions.PSC`.
- Each VRChat group role becomes its own PSC group in the form:
  >> RoleName > RoleName
  Username1
  Username2

Notes
- The VRChat account used by the action must be a member of the groups you track.
- If your target repository uses different internal variable/type names for role objects or maps, a small adaptation (see TODOs in Program.cs insert) may be required.
```