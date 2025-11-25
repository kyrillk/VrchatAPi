using CommandLine;
using Discord;
using Discord.WebSocket;
using Kemocade.Vrc.Api.Tracker.Action;
using OtpNet;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using VRChat.API.Api;
using VRChat.API.Client;
using VRChat.API.Model;
using static Kemocade.Vrc.Api.Tracker.Action.TrackedData;
using static Kemocade.Vrc.Api.Tracker.Action.TrackedData.TrackedDiscordServer;
using static Kemocade.Vrc.Api.Tracker.Action.TrackedData.TrackedVrcGroup;


using static System.Console;
using static System.IO.File;
using static System.Text.Json.JsonSerializer;

// Constants
const string USR_PREFIX = "usr_";
const int USR_LENGTH = 40;
const int DISCORD_MAX_ATTEMPTS = 5;
const int DISCORD_MAX_MESSAGES = 100000;

// Configure Cancellation
using CancellationTokenSource tokenSource = new();
CancelKeyPress += delegate { tokenSource.Cancel(); };

// Configure Inputs
ParserResult<ActionInputs> parser = Parser.Default.ParseArguments<ActionInputs>(args);
if (parser.Errors.ToArray() is { Length: > 0 } errors)
{
    foreach (CommandLine.Error error in errors)
    { WriteLine($"{nameof(error)}: {error.Tag}"); }
    Environment.Exit(2);
    return;
}
ActionInputs inputs = parser.Value;

bool useWorlds = !string.IsNullOrEmpty(inputs.Worlds);
bool useGroups = !string.IsNullOrEmpty(inputs.Groups);
bool useDiscord = !string.IsNullOrEmpty(inputs.Bot) &&
    !string.IsNullOrEmpty(inputs.Discords) &&
    !string.IsNullOrEmpty(inputs.Channels);

// Parse delimeted inputs
string[] worldIds = useWorlds ?
     inputs.Worlds.Split(',') : [];
string[] groupIds = useGroups ?
     inputs.Groups.Split(',') : [];
ulong[] servers = useDiscord ?
     inputs.Discords.Split(',').Select(ulong.Parse).ToArray() : [];
ulong[] channels = useDiscord ?
    inputs.Channels.Split(',').Select(ulong.Parse).ToArray() : [];

// Ensure parallel Discord input arrays are equal lengths
if (servers.Length != channels.Length)
{
    WriteLine("Discord Servers Array and Channels Array must have the same Length!");
    Environment.Exit(2);
    return;
}
Dictionary<ulong, ulong> discordServerIdsToChannelIds =
    Enumerable.Range(0, servers.Length)
    .ToDictionary(i => servers[i],i => channels[i]);

// Find Local Files
DirectoryInfo workspace = new(inputs.Workspace);
DirectoryInfo output = workspace.CreateSubdirectory(inputs.Output);

// Discord bot tasks
DiscordSocketClient _discordBot = new();
if (useDiscord)
{
    WriteLine("Logging in to Discord Bot...");
    await _discordBot.LoginAsync(TokenType.Bot, inputs.Bot);
    await _discordBot.StartAsync();

    while
    (
        _discordBot.LoginState != LoginState.LoggedIn ||
        _discordBot.ConnectionState != ConnectionState.Connected
    )
    { await WaitSeconds(1); }
    WriteLine("Logged in to Discord Bot!");
}
else
{
    WriteLine("Skipping Discord Integration...");
}

// Map Discord Servers to Server Names, VRC User Roles, and All Roles
Dictionary<ulong, string> discordGuildIdsToDiscordServerNames = [];
Dictionary<ulong, int> discordGuildIdsToDiscordMemberCounts = [];
Dictionary<ulong, Dictionary<string, SocketRole[]>> discordGuildIdsToVrcUserIdsToDiscordRoles = [];
Dictionary<ulong, SocketRole[]> discordGuildIdsToAllDiscordRoles = [];
foreach (KeyValuePair<ulong, ulong> kvp in discordServerIdsToChannelIds )
{
    ulong discordGuildId = kvp.Key;
    ulong discordChannelId = kvp.Value;

    WriteLine($"Getting Discord Users from server {discordGuildId}...");
    SocketGuild socketGuild = _discordBot.GetGuild(discordGuildId);
    await WaitSeconds(5);
    SocketTextChannel socketChannel = socketGuild.GetTextChannel(discordChannelId);
    await WaitSeconds(5);
    IGuildUser[] serverUsers = (await socketGuild.GetUsersAsync().FlattenAsync()).ToArray();
    await WaitSeconds(5);
    WriteLine($"Got Discord Users: {serverUsers.Length}");

    // Get all messages from channel, try up to DISCORD_ATTEMPTS times if fails
    WriteLine($"Getting VRC-Discord connections from server {discordGuildId} channel {discordChannelId}...");
    IEnumerable<IMessage> messages = null;
    for (int attempt = 0; messages is null && attempt < DISCORD_MAX_ATTEMPTS; attempt++)
    {
        messages = await socketChannel
            .GetMessagesAsync(DISCORD_MAX_MESSAGES)
            .FlattenAsync();

        if (messages is null)
        {
            WriteLine($"Getting messages failed, retrying ({attempt}/{DISCORD_MAX_ATTEMPTS})...");
            await WaitSeconds(30);
        }
    }

    // Build a mapping of VRC IDs to Discord Roles that prevents duplicates in both directions
    Dictionary<string, SocketRole[]> vrcUserIdsToDiscordRoles = messages
        // Prioritize the newest messages
        .OrderByDescending(m => m.Timestamp)
        .Select(m => (VrcId: GetVrcId(m), DiscordUser: m.Author))
        // Validate VRC ID format & ensure author is still in the server
        .Where
        (
            m =>
            !string.IsNullOrEmpty(m.VrcId) &&
            serverUsers.Any(u => m.DiscordUser.Id == u.Id)
        )
        .DistinctBy(m => m.DiscordUser.Id)
        .DistinctBy(m => m.VrcId)
        // Get all roles for each user
        .ToDictionary
        (
            m => m.VrcId,
            m => serverUsers
                .First(su => su.Id == m.DiscordUser.Id)
                .RoleIds
                .Select(r => socketGuild.GetRole(r))
                .ToArray()
        );

    WriteLine($"Got VRC-Discord connections: {vrcUserIdsToDiscordRoles.Count}");

    // Store all gathered information about the Discord Server
    discordGuildIdsToDiscordServerNames.Add(discordGuildId, socketGuild.Name);
    discordGuildIdsToDiscordMemberCounts.Add(discordGuildId, socketGuild.MemberCount);
    discordGuildIdsToVrcUserIdsToDiscordRoles.Add(discordGuildId, vrcUserIdsToDiscordRoles);
    discordGuildIdsToAllDiscordRoles.Add
    (
        discordGuildId,
        vrcUserIdsToDiscordRoles
            .SelectMany(kvp => kvp.Value)
            .DistinctBy(r => r.Id)
            .ToArray()
    );
}

// Store data as it is collected from the API
// World Data
Dictionary<string, World> vrcWorldIdsToWorldModels = [];
// Group Data
Dictionary<string, VRChat.API.Model.Group> vrcGroupIdsToGroupModels = [];
Dictionary<string, GroupRole[]> vrcGroupIdsToAllVrcRoles = [];
Dictionary<string, Dictionary<string, string[]>> vrcGroupIdsToVrcDisplayNamesToVrcRoleIds = [];
// Discord Data
Dictionary<ulong, Dictionary<string, SocketRole[]>> discordGuildIdsToVrcDisplayNamesToDiscordRoles = [];
// Handle API exceptions
try
{
    // Authentication credentials
    Configuration config = new()
    {
        Username = inputs.Username,
        Password = inputs.Password,
        UserAgent = "kemocade/0.0.1 admin%40kemocade.com"
    };

    // Create a shared ApiClient for session/cookie management
    ApiClient apiClient = new();

    // Create instances of APIs using the shared ApiClient
    AuthenticationApi authApi = new(apiClient, apiClient, config);
    WorldsApi worldsApi = new(apiClient, apiClient, config);
    UsersApi usersApi = new(apiClient, apiClient, config);
    GroupsApi groupsApi = new(apiClient, apiClient, config);

    // Log in
    WriteLine("Logging in...");
    CurrentUser currentUser = authApi.GetCurrentUser();
    await WaitSeconds(1);

    // Check if 2FA is needed
    if (currentUser == null)
    {
        WriteLine("2FA needed...");
    
        // Normalize and decode the key
        string rawKey = inputs.Key ?? string.Empty;
        rawKey = rawKey.Replace(" ", string.Empty).Trim();
        // If someone pasted an otpauth URI, strip it
        if (rawKey.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
        {
            // otpauth://totp/Label?secret=SECRET&...
            var m = Regex.Match(rawKey, @"[&?]secret=([^&]+)", RegexOptions.IgnoreCase);
            if (m.Success) rawKey = m.Groups[1].Value;
        }
        string key = Regex.Replace(rawKey.ToUpperInvariant(), @"[^A-Z2-7]", string.Empty);
    
        // For debugging only: print timestamp (do NOT print key or full code in prod)
        WriteLine($"Local UTC time: {DateTimeOffset.UtcNow:O}");
    
        byte[] secretBytes;
        try
        {
            secretBytes = Base32Encoding.ToBytes(key);
        }
        catch (Exception ex)
        {
            WriteLine($"Failed to decode 2FA key: {ex.Message}");
            Environment.Exit(2);
            return;
        }
    
        var totp = new Totp(secretBytes);
    
        // If we're very close to boundary, wait for next token
        int remainingSeconds = totp.RemainingSeconds();
        if (remainingSeconds < 5)
        {
            WriteLine("Waiting for new token...");
            await Task.Delay(TimeSpan.FromSeconds(remainingSeconds + 1));
            totp = new Totp(secretBytes); // re-create to be safe
        }
    
        // Try a few times to tolerate small clock drift / latency
        const int maxAttempts = 3;
        bool ok = false;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            string code = totp.ComputeTotp(); // compute right before call
            WriteLine($"Using 2FA code: {code}(attempt {attempt})");
    
            try
            {
                // If Verify2FA has a return value, prefer checking it; otherwise check currentUser afterward
                var result = authApi.Verify2FA(new(code));
                WriteLine($"Verify2FA result: {result}");
            }
            catch (Exception ex)
            {
                WriteLine($"Verify2FA threw: {ex.Message}");
            }
    
            currentUser = authApi.GetCurrentUser();
            await WaitSeconds(1);

    
            if (currentUser != null)
            {
                ok = true;
                break;
            }
    
            int rem = totp.RemainingSeconds();
            WriteLine($"Verify failed, token remaining seconds: {rem}");
            if (attempt < maxAttempts)
            {
                // Sleep into next time window if needed
                await Task.Delay(1000);
            }
        }
    
        if (!ok)
        {
            WriteLine("Failed to validate 2FA!");
            Environment.Exit(2);
            return;
        }
    }
    WriteLine($"Logged in as {currentUser.DisplayName}");

    // Get all info from all tracked worlds
    foreach (string worldId in worldIds)
    {
        // Get World
        World world = worldsApi.GetWorld(worldId);
        WriteLine($"Got World: {worldId}");
        vrcWorldIdsToWorldModels.Add(worldId, world);
        await WaitSeconds(1);
    }

    // Get all users and roles from all tracked groups
    foreach (string groupId in groupIds)
    {
        // Get group
        VRChat.API.Model.Group group = groupsApi.GetGroup(groupId);
        int memberCount = group.MemberCount;
        WriteLine($"Got Group {group.Name}, Members: {memberCount}");

        // Ensure the Local User is in the VRC Group
        GroupMyMember self = group.MyMember;
        if (self == null || self.UserId != currentUser.Id)
        {
            WriteLine("Local User must be a member of the VRC Group!");
            Environment.Exit(2);
            return;
        }

        // Get group members
        WriteLine("Getting Group Members...");
        List<GroupMember> groupMembers = [];

        // Get group members and add to group members list
        while (groupMembers.Count < memberCount - 1)
        {
            groupMembers.AddRange
                (groupsApi.GetGroupMembers(groupId, n: 100, offset: groupMembers.Count, sort: GroupSearchSort.Asc));
            WriteLine(groupMembers.Count);
            await WaitSeconds(1);
        }

        // Map Group Members to Roles
        Dictionary<string, string[]> groupDisplayNamesToVrcRoleIds =
            groupMembers.ToDictionary
            (
                m => m.User.DisplayName,
                m => m.RoleIds.ToArray()
            );

        // Get All Group Roles
        WriteLine("Getting Group Roles...");
        List<GroupRole> groupRoles = groupsApi.GetGroupRoles(groupId);
        WriteLine($"Got Group Roles: {groupRoles.Count}");

        // Store all gathered information about the VRC Group
        vrcGroupIdsToGroupModels.Add(groupId, group);
        vrcGroupIdsToVrcDisplayNamesToVrcRoleIds
            .Add(groupId, groupDisplayNamesToVrcRoleIds);
        vrcGroupIdsToAllVrcRoles.Add(group.Id, [..groupRoles]);
    }

    // Pull Discord Users from the VRC API
    WriteLine("Getting Discord Users...");
    discordGuildIdsToVrcDisplayNamesToDiscordRoles =
        discordGuildIdsToDiscordServerNames.Keys
        .ToDictionary(d => d, d => new Dictionary<string, SocketRole[]>());

    // Iterate over each Discord Guild
    foreach (ulong discordGuildId in discordGuildIdsToVrcDisplayNamesToDiscordRoles.Keys)
    {
        // Find the current Discord Guild's VRC User ID to Discord Role mapping
        Dictionary<string, SocketRole[]> vrcUserIdsToDiscordRoles =
            discordGuildIdsToVrcUserIdsToDiscordRoles[discordGuildId];
        WriteLine($"Checking Discord Guild: {discordGuildId} ({vrcUserIdsToDiscordRoles.Keys.Count} Linked VRC Users)...");

        // Iterate over each VRC User ID in the Discord Guild
        foreach (string vrcUserId in vrcUserIdsToDiscordRoles.Keys)
        {
            WriteLine($"Getting Discord Linked VRC User: {vrcUserId}...");
            // Get the current VRC User's information from the VRC API
            User user = usersApi.GetUser(vrcUserId);
            await WaitSeconds(1);

            // Get the current VRC User's roles in the current Discord Guild
            SocketRole[] discordRoles = vrcUserIdsToDiscordRoles[vrcUserId];

            // Map the VRC User to their Discord Guild roles
            discordGuildIdsToVrcDisplayNamesToDiscordRoles[discordGuildId]
                .Add(user.DisplayName, discordRoles);
        }
    }
}
catch (ApiException e)
{
    WriteLine("Exception when calling API: {0}", e.Message);
    WriteLine("Status Code: {0}", e.ErrorCode);
    WriteLine(e.ToString());
    Environment.Exit(2);
    return;
}

// Combine all unique VRC Display Names across Groups and Discords
string[] vrcUserDisplayNames = vrcGroupIdsToVrcDisplayNamesToVrcRoleIds
    .SelectMany(g => g.Value.Keys)
    .Concat
    (
        discordGuildIdsToVrcDisplayNamesToDiscordRoles
        .SelectMany(d => d.Value.Keys)
    )
    .Distinct()
    .OrderBy(n => n)
    .ToArray();

int GetVrcUserIndex(string displayName) =>
    Array.IndexOf(vrcUserDisplayNames, displayName);

TrackedData data = new()
{
    FileTimeUtc = DateTime.Now.ToFileTimeUtc(),
    VrcUserDisplayNames = vrcUserDisplayNames,
    VrcWorldsById = vrcWorldIdsToWorldModels.
        ToDictionary
        (
            kvp => kvp.Key,
            kvp => new TrackedVrcWorld
            {
                Name = kvp.Value.Name,
                Visits = kvp.Value.Visits,
                Favorites = kvp.Value.Favorites,
                Occupants = kvp.Value.Occupants
            }
        ),
    VrcGroupsById = vrcGroupIdsToVrcDisplayNamesToVrcRoleIds
        .ToDictionary
        (
            kvp => kvp.Key,
            kvp => new TrackedVrcGroup
            {
                Name = vrcGroupIdsToGroupModels[kvp.Key].Name,
                VrcUsers = kvp.Value.Keys
                    .Select(n => GetVrcUserIndex(n))
                    .Where(i => i != -1)
                    .ToArray(),
                Roles = vrcGroupIdsToAllVrcRoles[kvp.Key]
                    .ToDictionary
                    (
                        r => r.Id,
                        r => new TrackedVrcGroupRole
                        {
                            Name = r.Name,
                            IsAdmin = r.Permissions.Contains(GroupPermissions.group_all),
                            IsModerator = r.Permissions.Contains(GroupPermissions.group_all) ||
                                r.Permissions.Contains(GroupPermissions.group_instance_moderate),
                            VrcUsers = kvp.Value
                                .Where(kvp2 => kvp2.Value.Contains(r.Id))
                                .Select(kvp2 => GetVrcUserIndex(kvp2.Key))
                                .ToArray()
                        }
                    )
            }
        ),
    DiscordServersById = discordGuildIdsToVrcDisplayNamesToDiscordRoles.ToDictionary
    (
        d => d.Key.ToString(),
        d => new TrackedDiscordServer
        {
            Name = discordGuildIdsToDiscordServerNames[d.Key],
            MemberCount = discordGuildIdsToDiscordMemberCounts[d.Key],
            VrcUsers = discordGuildIdsToVrcDisplayNamesToDiscordRoles[d.Key]
                .Select(m => GetVrcUserIndex(m.Key))
                .Where(i => i != -1)
                .ToArray(),
            Roles = discordGuildIdsToAllDiscordRoles[d.Key]
                .ToDictionary
                (
                    r => r.Id.ToString(),
                    r => new TrackedDiscordServerRole
                    {
                        Name = r.Name,
                        IsAdmin = r.Permissions.Administrator,
                        IsModerator = r.Permissions.Administrator ||
                            r.Permissions.ModerateMembers,
                        VrcUsers = discordGuildIdsToVrcDisplayNamesToDiscordRoles[d.Key]
                            .Where(kvp => kvp.Value.Any(sr => sr.Id == r.Id))
                            .Select(u => GetVrcUserIndex(u.Key))
                            .ToArray()
                    }
                )
        }
    )
};

// Build Json from data
JsonSerializerOptions options = new()
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault
};
string dataJsonString = Serialize(data, options);
WriteLine(dataJsonString);

// Write Json to file
FileInfo dataJsonFile = new(Path.Join(output.FullName, "data.json"));
WriteAllText(dataJsonFile.FullName, dataJsonString);

// Generate PSC file if enabled
bool usePsc = !string.IsNullOrEmpty(inputs.Psc) &&
    inputs.Psc.Equals("true", StringComparison.OrdinalIgnoreCase);

if (usePsc)
{
    // Only attempt PSC generation if group tracking/mappings are present
    try
    {
        WriteLine("PSC generation requested...");

        // NOTE: variable names below are taken from the original action layout.
        // If the target repo uses different variable names for these maps/arrays,
        // replace them accordingly:
        //
        // - groupIds                     : string[] of tracked group ids
        // - vrcGroupIdsToAllVrcRoles     : Dictionary<string, GroupRole[]>
        // - vrcGroupIdsToVrcDisplayNamesToVrcRoleIds : Dictionary<string, Dictionary<string, string[]>>
        // - vrcUserDisplayNames          : string[] of display names
        //
        // If names differ, adapt or leave a TODO for maintainers.

        if (groupIds == null || groupIds.Length == 0)
        {
            WriteLine("No groupIds found; skipping PSC generation.");
        }
        else if (vrcGroupIdsToAllVrcRoles == null || vrcGroupIdsToVrcDisplayNamesToVrcRoleIds == null)
        {
            WriteLine("Required role mappings not present; skipping PSC generation.");
        }
        else
        {
            StringBuilder pscBuilder = new();
            pscBuilder.AppendLine("// Auto-generated PSC file for PermissionManager");
            pscBuilder.AppendLine("// https://github.com/MagmaMCNet/PermissionManager");
            pscBuilder.AppendLine($"// Generated at: {DateTime.UtcNow.ToString("o")}");
            pscBuilder.AppendLine();
            pscBuilder.AppendLine("// Formatting");
            pscBuilder.AppendLine("// >> - New Group");
            pscBuilder.AppendLine("// > - Permission Statement");
            pscBuilder.AppendLine("// + - Add extra Permission");
            pscBuilder.AppendLine();

            foreach (string groupId in groupIds)
            {
                if (!vrcGroupIdsToAllVrcRoles.ContainsKey(groupId)) continue;
                if (!vrcGroupIdsToVrcDisplayNamesToVrcRoleIds.ContainsKey(groupId)) continue;

                // roles: array/list of role objects for this group
                var roles = vrcGroupIdsToAllVrcRoles[groupId];
                var displayNameToRoleIds = vrcGroupIdsToVrcDisplayNamesToVrcRoleIds[groupId];

                // Defensive: skip if null
                if (roles == null) continue;
                if (displayNameToRoleIds == null) continue;

                // For each role in the group, create a PSC block
                foreach (var role in roles)
                {
                    // role.Id and role.Name are expected properties. If your role type uses
                    // different property names, update the references below.
                    string roleId = role.Id;
                    string roleName = role.Name?.Trim() ?? roleId;

                    // Collect display names that include this roleId
                    var usersWithRole = displayNameToRoleIds
                        .Where(kvp => kvp.Value != null && kvp.Value.Contains(roleId))
                        .Select(kvp => kvp.Key?.Trim())
                        .Where(name => !string.IsNullOrEmpty(name))
                        .OrderBy(n => n)
                        .ToList();

                    // Skip empty role blocks if no users
                    if (usersWithRole.Count == 0)
                    {
                        // Still write empty role header if you prefer; currently we will still write it.
                    }

                    pscBuilder.AppendLine($">> {roleName} > {roleName}");
                    foreach (var user in usersWithRole)
                    {
                        pscBuilder.AppendLine(user);
                    }
                    pscBuilder.AppendLine();
                }
            }

            // Write to Permissions.PSC in the same output directory
            FileInfo pscFile = new(Path.Join(output.FullName, "Permissions.PSC"));
            WriteAllText(pscFile.FullName, pscBuilder.ToString());
            WriteLine($"PSC file written to: {pscFile.FullName}");
        }
    }
    catch (Exception ex)
    {
        // Do not fail the entire action on PSC generation errors; log and continue.
        WriteLine($"Failed to generate PSC: {ex.Message}");
    }
}

WriteLine("Done!");
Environment.Exit(0);

static string GetVrcId(IMessage message)
{
    // Ensure the content contains a VRC User ID Prefix
    string content = message.Content;
    if (!content.Contains(USR_PREFIX)) { return string.Empty; }

    // Ensure there are enough characters following the string to extract a full User ID
    int lastIndex = content.LastIndexOf(USR_PREFIX);
    if (content.Length - lastIndex < USR_LENGTH) { return string.Empty; }

    // Ensure the userId contains a valid GUID
    string candidate = content.Substring(lastIndex, USR_LENGTH);
    if (!Guid.TryParse(candidate.AsSpan(USR_PREFIX.Length), out _)) { return string.Empty; }

    return candidate.ToLowerInvariant();
}

static async Task WaitSeconds(int seconds) =>
    await Task.Delay(TimeSpan.FromSeconds(seconds));
