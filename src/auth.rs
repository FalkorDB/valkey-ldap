use std::os::raw::c_int;

use log::{debug, error};
use valkey_module::BlockedClient;
use valkey_module::{AUTH_HANDLED, AUTH_NOT_HANDLED, Context, Status, ValkeyError, ValkeyString};

use crate::configs;
use crate::vkldap;
use crate::vkldap::errors::VkLdapError;

fn auth_reply_callback(
    ctx: &Context,
    username: ValkeyString,
    _: ValkeyString,
    priv_data: Option<&Result<Vec<String>, VkLdapError>>,
) -> Result<c_int, ValkeyError> {
    if let Some(res) = priv_data {
        match res {
            Ok(tokens_from_ldap) => {
                // Only apply dynamic ACL rules if LDAP tokens were found
                // This preserves backward compatibility with pre-configured users
                if !tokens_from_ldap.is_empty() {
                    // Build ACL rules: defaults + LDAP-provided tokens
                    let mut rule_tokens: Vec<String> = configs::get_default_acl_rules(ctx);
                    rule_tokens.extend(tokens_from_ldap.iter().cloned());

                    // Apply ACL SETUSER <username> <rules...>
                    let uname = username.to_string();
                    let mut args: Vec<String> = Vec::with_capacity(2 + rule_tokens.len());
                    args.push("SETUSER".to_string());
                    args.push(uname.clone());
                    args.extend(rule_tokens);

                    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                    if let Err(e) = ctx.call("ACL", &arg_refs[..]) {
                        error!("failed to set ACL for user {uname}: {e}");
                        return Err(ValkeyError::Str("Failed to apply ACL rules"));
                    }
                }

                match ctx.authenticate_client_with_acl_user(&username) {
                    Status::Ok => {
                        debug!("successfully authenticated LDAP user {username}");
                        Ok(AUTH_HANDLED)
                    }
                    Status::Err => Err(ValkeyError::Str("Failed to authenticate with ACL")),
                }
            }
            Err(err) => {
                debug!("failed to authenticate LDAP user {username}");
                error!("LDAP authentication failure: {err}");
                Ok(AUTH_NOT_HANDLED)
            }
        }
    } else {
        Err(ValkeyError::Str(
            "Unknown error during authentication, check the server logs",
        ))
    }
}

fn free_callback(_: &Context, _: Result<Vec<String>, VkLdapError>) {}

pub fn ldap_auth_blocking_callback(
    ctx: &Context,
    username: ValkeyString,
    password: ValkeyString,
) -> Result<c_int, ValkeyError> {
    if !configs::is_auth_enabled(ctx) {
        return Ok(AUTH_NOT_HANDLED);
    }

    let user_str = username.to_string();

    // Check if the user is exempted from LDAP authentication
    if configs::is_user_exempted_from_ldap(&user_str) {
        debug!("user {user_str} is exempted from LDAP authentication");
        return Ok(AUTH_NOT_HANDLED);
    }

    debug!("starting authentication for user={username}");

    let use_bind_mode = configs::is_bind_mode(ctx);

    let pass_str = password.to_string();

    let blocked_client = ctx.block_client_on_auth(auth_reply_callback, Some(free_callback));

    let callback =
        move |blocked_client: Option<BlockedClient<Result<Vec<String>, VkLdapError>>>, result| {
            assert!(blocked_client.is_some());
            let mut blocked_client = blocked_client.unwrap();
            if let Err(e) = blocked_client.set_blocked_private_data(result) {
                error!("failed to set the auth callback result: {e}");
            }
        };

    let res = if use_bind_mode {
        vkldap::vk_ldap_bind_and_group_rules(user_str, pass_str, callback, blocked_client)
    } else {
        vkldap::vk_ldap_search_bind_and_group_rules(user_str, pass_str, callback, blocked_client)
    };

    match res {
        Ok(_) => Ok(AUTH_HANDLED),
        Err(err) => {
            error!("failed to submit ldap bind request: {err}");
            Ok(AUTH_NOT_HANDLED)
        }
    }
}
