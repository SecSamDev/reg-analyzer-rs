
pub mod shellbag;
mod modern;
use std::collections::BTreeMap;

use self::shellbag::ShellBags;

use forensic_rs::prelude::{RegistryReader, ForensicResult, Bitacora};



pub fn read_shell_bags_current_user(registry : &mut impl RegistryReader) -> ForensicResult<Bitacora<ShellBags>> {
    if is_win_vista(registry) {
        ForensicResult::Err(forensic_rs::prelude::ForensicError::NoMoreData)
    }else if is_win_xp(registry) {
        ForensicResult::Err(forensic_rs::prelude::ForensicError::NoMoreData)
    }else if is_win_modern(registry) {
        modern::read_shell_bags_current_user(registry)
    }else {
        ForensicResult::Err(forensic_rs::prelude::ForensicError::NoMoreData)
    }

}


pub fn read_shell_bags_user(registry : &mut impl RegistryReader, user : &str) -> ForensicResult<Bitacora<ShellBags>> {
    if is_win_vista(registry) {
        ForensicResult::Err(forensic_rs::prelude::ForensicError::NoMoreData)
    }else if is_win_xp(registry) {
        ForensicResult::Err(forensic_rs::prelude::ForensicError::NoMoreData)
    }else if is_win_modern(registry) {
        modern::read_shell_bags_user(registry, user)
    }else {
        ForensicResult::Err(forensic_rs::prelude::ForensicError::NoMoreData)
    }

}

pub fn read_all_shell_bags(registry : &mut impl RegistryReader) -> ForensicResult<BTreeMap<String, Bitacora<ShellBags>>> {
    let mut user_map = BTreeMap::new();
    for user in registry.enumerate_keys(forensic_rs::prelude::RegHiveKey::HkeyUsers)? {
        if !user.starts_with("S-"){
            continue;
        }
        let shell_item = match read_shell_bags_user(registry, &user) {
            Ok(v) => v,
            Err(_) => continue
        };
        user_map.insert(user, shell_item);
    }
    Ok(user_map)

}


pub fn is_win_xp(registry : &mut impl RegistryReader) -> bool {
    match registry.open_key(forensic_rs::prelude::RegHiveKey::HkeyCurrentUser, "Software\\Microsoft\\Windows\\ShellNoRoam\\Bags") {
        Ok(_v) => true,
        Err(_) => false
    }
}

pub fn is_win_vista(registry : &mut impl RegistryReader) -> bool {
    match registry.open_key(forensic_rs::prelude::RegHiveKey::HkeyCurrentUser, "Software\\Microsoft\\Windows\\ShellNoRoam\\Bags") {
        Ok(_v) => (),
        Err(_) => return false
    };
    match registry.open_key(forensic_rs::prelude::RegHiveKey::HkeyClassesRoot, "Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags") {
        Ok(_v) => (),
        Err(_) => return false
    };
    true
}

pub fn is_win_modern(registry : &mut impl RegistryReader) -> bool {
    match registry.open_key(forensic_rs::prelude::RegHiveKey::HkeyCurrentUser, "Software\\Microsoft\\Windows\\ShellNoRoam\\Bags") {
        Ok(_v) => return false,
        Err(_) => ()
    };
    match registry.open_key(forensic_rs::prelude::RegHiveKey::HkeyClassesRoot, "Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags") {
        Ok(_v) => (),
        Err(_) => return false
    };
    match registry.open_key(forensic_rs::prelude::RegHiveKey::HkeyCurrentUser, "Software\\Microsoft\\Windows\\Shell\\Bags") {
        Ok(_v) => (),
        Err(_) => return false
    };
    true
}


#[cfg(test)]
mod test_shellbags {
    use super::modern::read_shell_bags_current_user;

    #[cfg(target_os = "windows")]
    #[test]
    fn test_shellbags() {
        let mut registry = frnsc_liveregistry_rs::LiveRegistryReader{};
        let bitacora = read_shell_bags_current_user(&mut registry).unwrap();
        assert!( bitacora.data.ntuser.list.len() > 0);
        assert!( bitacora.data.usr_class.list.len() > 0);
    }
        
}