use std::{collections::BTreeMap, convert::TryInto};

use chrono::{Utc, TimeZone};
use forensic_rs::prelude::{RegHiveKey, ForensicResult, RegistryReader, RegValue, ForensicError, Bitacora};
use uuid::Uuid;

use super::shellbag::{ShellBagList, WindowBagInfo, NodeSlot, ShellBagPath, ShellVolumeItem, ShellItem, ShellNetworkItem, ShellFileItem, ShellFolderItem, ShellBags};

const PARSER_NAME : &'static str = "ShellBagModern";

pub fn read_shell_bags_current_user(registry : &mut impl RegistryReader) -> ForensicResult<Bitacora<ShellBags>>{
    let shell_key = get_shell_key_usrclass(registry, RegHiveKey::HkeyClassesRoot)?;
    let bags_key = get_bags_key(registry, shell_key)?;
    let mru_bag_key = get_mrubag_key(registry, shell_key)?;
    let mut bags_usrclass = read_all_bags(registry, bags_key)?;
    read_mru_bag(registry, mru_bag_key, &mut bags_usrclass, &vec![])?;
    let shell_key = get_shell_key_ntuser(registry, RegHiveKey::HkeyCurrentUser)?;
    let bags_key = get_bags_key(registry, shell_key)?;
    let mru_bag_key = get_mrubag_key(registry, shell_key)?;
    let mut bags_ntuser = read_all_bags(registry, bags_key)?;
    read_mru_bag(registry, mru_bag_key, &mut bags_ntuser, &vec![])?;
    let mut bitacora : Bitacora<ShellBags> = Bitacora::default();
    bitacora.copy_errors(&mut bags_ntuser.errors);
    bitacora.copy_errors(&mut bags_usrclass.errors);
    bitacora.data.ntuser = bags_ntuser.data;
    bitacora.data.usr_class = bags_usrclass.data;
    Ok(bitacora)
}

pub fn read_shell_bags_user(registry : &mut impl RegistryReader, user : &str) -> ForensicResult<Bitacora<ShellBags>>{
    let user_key = registry.open_key(RegHiveKey::HkeyUsers, user)?;
    let user_class_key = registry.open_key(user_key, &format!("SOFTWARE\\Classes"))?;
    let shell_key = get_shell_key_usrclass(registry, user_class_key)?;
    let bags_key = get_bags_key(registry, shell_key)?;
    let mru_bag_key = get_mrubag_key(registry, shell_key)?;
    let mut bags_usrclass = read_all_bags(registry, bags_key)?;
    read_mru_bag(registry, mru_bag_key, &mut bags_usrclass, &vec![])?;
    let shell_key = get_shell_key_ntuser(registry, user_key)?;
    let bags_key = get_bags_key(registry, shell_key)?;
    let mru_bag_key = get_mrubag_key(registry, shell_key)?;
    let mut bags_ntuser = read_all_bags(registry, bags_key)?;
    read_mru_bag(registry, mru_bag_key, &mut bags_ntuser, &vec![])?;
    let mut bitacora : Bitacora<ShellBags> = Bitacora::default();
    bitacora.copy_errors(&mut bags_ntuser.errors);
    bitacora.copy_errors(&mut bags_usrclass.errors);
    bitacora.data.ntuser = bags_ntuser.data;
    bitacora.data.usr_class = bags_usrclass.data;
    Ok(bitacora)
}

pub fn get_shell_key_usrclass(registry : &mut impl RegistryReader, hkey : RegHiveKey) -> ForensicResult<RegHiveKey> {
    registry.open_key(hkey, "Local Settings\\Software\\Microsoft\\Windows\\Shell")
}

pub fn get_shell_key_ntuser(registry : &mut impl RegistryReader, hkey : RegHiveKey) -> ForensicResult<RegHiveKey> {
    registry.open_key(hkey, "Software\\Microsoft\\Windows\\Shell")
}

pub fn get_bags_key(registry : &mut impl RegistryReader, hkey : RegHiveKey) -> ForensicResult<RegHiveKey> {
    registry.open_key(hkey, "Bags")
}

pub fn get_mrubag_key(registry : &mut impl RegistryReader, hkey : RegHiveKey) -> ForensicResult<RegHiveKey> {
    registry.open_key(hkey, "BagMRU")
}

pub fn read_all_bags(registry : &mut impl RegistryReader, bags_key : RegHiveKey) -> ForensicResult<Bitacora<ShellBagList>> {
    let list = ShellBagList::new();
    let mut bitacora = Bitacora::new(list);
    let key_names = match registry.enumerate_keys(bags_key) {
        Ok(v) => v,
        Err(e) => {
            match e {
                forensic_rs::prelude::ForensicError::NoMoreData => vec![],
                _ => return Err(e)
            }
        }
    };
    for key_name in key_names {
        let node_slot = match key_name.parse::<u32>() {
            Ok(v) => v,
            Err(_) => {
                bitacora.add_error(PARSER_NAME, format!("Bag {}",key_name), ForensicError::BadFormat);
                continue;
            }
        };
        match read_windows_in_bag(registry, bags_key, node_slot) {
            Ok(v) => {
                bitacora.data.node_slots.insert(NodeSlot(node_slot), v);
            },
            Err(err) => {
                bitacora.add_error(PARSER_NAME, format!("Bag {}",key_name), err);
                continue;
            }
        };
    }
    Ok(bitacora)
}

pub fn read_windows_in_bag(registry : &mut impl RegistryReader, bags_key : RegHiveKey, node_slot : u32) -> ForensicResult<BTreeMap<String, WindowBagInfo>> {
    let mut list_of_windows = BTreeMap::new();
    let node_key = registry.open_key(bags_key, &format!("{}",node_slot))?;
    let window_name_list = registry.enumerate_keys(node_key)?;
    for window_name in window_name_list {
        let mut info = WindowBagInfo::default();
        info.slot = node_slot;
        let subnode_key = registry.open_key(node_key, &window_name)?;
        let uuid = registry.key_at(subnode_key, 0)?;
        let uuid_key = registry.open_key(subnode_key, &uuid)?;
        match registry.read_value(uuid_key, "FFlags") {
            Ok(v) => match v {
                RegValue::DWord(v) => info.f_flags = v,
                _ => {}
            },
            Err(_) => {}
        };
        match registry.read_value(uuid_key, "GroupByDirection") {
            Ok(v) => match v {
                RegValue::DWord(v) => info.group_by_direction = v,
                _ => {}
            },
            Err(_) => {}
        };
        match registry.read_value(uuid_key, "GroupByKey:PID") {
            Ok(v) => match v {
                RegValue::DWord(v) => info.group_by_key_pid = v,
                _ => {}
            },
            Err(_) => {}
        };
        match registry.read_value(uuid_key, "GroupView") {
            Ok(v) => match v {
                RegValue::DWord(v) => info.group_view = v,
                _ => {}
            },
            Err(_) => {}
        };
        match registry.read_value(uuid_key, "IconSize") {
            Ok(v) => match v {
                RegValue::DWord(v) => info.icon_size = v,
                _ => {}
            },
            Err(_) => {}
        };
        match registry.read_value(uuid_key, "LogicalViewMode") {
            Ok(v) => match v {
                RegValue::DWord(v) => info.logical_view_mode = v,
                _ => {}
            },
            Err(_) => {}
        };
        match registry.read_value(uuid_key, "Mod") {
            Ok(v) => match v {
                RegValue::DWord(v) => info.mode = v,
                _ => {}
            },
            Err(_) => {}
        };
        match registry.read_value(uuid_key, "Rev") {
            Ok(v) => match v {
                RegValue::DWord(v) => info.rev = v,
                _ => {}
            },
            Err(_) => {}
        };
        match registry.read_value(uuid_key, "Vid") {
            Ok(v) => match v {
                RegValue::SZ(v) => info.vid = Uuid::parse_str(&v[1..v.len() - 1]).unwrap_or_default().as_u128(),
                _ => {}
            },
            Err(_) => {}
        };
        list_of_windows.insert(window_name, info);
    }
    
    //Open <xxx>\Shell\<uuid>   
    Ok(list_of_windows)
}


pub fn read_mru_bag(registry : &mut impl RegistryReader, bag_mru_key : RegHiveKey, mut data : &mut Bitacora<ShellBagList>, parent_route : &Vec<u32>) -> ForensicResult<()> {
    let mru_list = get_mru_list(registry, bag_mru_key)?;
    let (mru_key_list, mru_key_list_str) : (Vec<u32>,Vec<String>) = match registry.enumerate_keys(bag_mru_key) {
        Ok(v) => {
            (v.iter().map(|v| v.parse::<u32>()).filter(|v| v.is_ok()).map(|v| v.unwrap_or_default()).collect(), v)
        },
        Err(e) => {
            data.add_error(PARSER_NAME, format!("MRU Bag {:?}", parent_route), ForensicError::Missing);
            return Err(e)
        }
    };

    let mut mru_key_list_ordered = mru_key_list.clone();
    mru_key_list_ordered.sort();

    let mut mru_list_ordered = mru_list.clone();
    mru_list_ordered.sort();
    
    
    let mut anomaly = false;
    for (a,b) in mru_key_list_ordered.iter().zip(mru_list_ordered.iter()) {
        if *a != *b {
            anomaly = true;
            println!("Anomaly: {:?} vs {:?}", mru_key_list_ordered, mru_list_ordered);
            break;
        }
    }
    for (node_slot, node_slot_str) in mru_key_list.iter().zip(&mru_key_list_str) {
        // TODO: detect anomalies
        let mut element_route = parent_route.clone();
        element_route.push(*node_slot);
        let (node_slot, node_value) = match registry.read_value(bag_mru_key, &node_slot_str) {
            Ok(v) => {
                let mut item = match v {
                    RegValue::Binary(v) => parse_node_value(&v, &element_route),
                    _ => {
                        data.add_error(PARSER_NAME, format!("MRU Bag {:?}", element_route) , ForensicError::BadFormat);
                        continue;
                    }
                };
                data.copy_errors(&mut item.errors);
                
                let item = match item.data {
                    Some(v) => v,
                    None => continue
                };
                let subnode_key = match registry.open_key(bag_mru_key, &node_slot_str) {
                    Ok(v) => v,
                    Err(_e) => continue
                };
                let _ = read_mru_bag(registry, subnode_key, &mut data, &element_route);
                let node_slot = match registry.read_value(subnode_key, "NodeSlot") {
                    Ok(v) => {
                        match v {
                            RegValue::DWord(v) => Some(v),
                            _ => {
                                data.add_error(PARSER_NAME, format!("MRU Bag {:?}", element_route) , ForensicError::BadFormat);
                                None
                            }
                        }
                    },
                    Err(err) => {
                        data.add_error(PARSER_NAME, format!("MRU Bag {:?}", element_route) , err);
                        None
                    }
                };
                (node_slot, item)
            },
            Err(_) => continue
        };
        
        data.data.list.insert(ShellBagPath(element_route), (node_slot, node_value));
    }
    if anomaly {
        data.data.mru_anomalies = Some((mru_list, mru_key_list));
    }
    Ok(())
}

pub fn get_mru_list(registry : &mut impl RegistryReader, bag_mru_key : RegHiveKey) -> ForensicResult<Vec<u32>> {
    let readed_data = match registry.read_value(bag_mru_key, "MRUListEx")? {
        RegValue::Binary(v) => v,
        _ => {
            return Err(ForensicError::Other(format!("Invalid format in MRUListEx")));
        }
    };
    if readed_data.len() < 8 {
        return Err(ForensicError::Other(format!("Invalid MRUListEx length")));
    }
    Ok(readed_data[0..readed_data.len() - 4].chunks(4).map(|v| u32::from_ne_bytes(v.try_into().unwrap())).collect())
}


pub fn parse_node_value(node_value : &Vec<u8>, element_route : &Vec<u32>) -> Bitacora<Option<ShellItem>> {
    
    if node_value.len() < 2 {
        return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::BadFormat);
    }
    let entry_size = u16::from_le_bytes(node_value[0..2].try_into().unwrap_or_else(|_| [0,0]));
    if entry_size < 20 {
        return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::BadFormat);
    }
    let entry_type : u8 = node_value[2];
    let is_file = (entry_type & 0x70) == 0x30;
    if is_file {
        return Bitacora::new(Some(
            {
                // File
                let mut item = ShellFileItem::default();
                item.fflags = u16::from_le_bytes(node_value[12..14].try_into().unwrap_or_else(|_| [0,0]));
                item.file_size = u32::from_le_bytes(node_value[4..8].try_into().unwrap_or_else(|_| [0,0,0,0]));
                match dosdate(&node_value[8..12]) {
                    Some(v) => {
                        item.m_time = v;
                    },
                    None => {}
                };
                let ext_offset = (node_value[entry_size as usize -2] as u16 | ((node_value[entry_size as usize -1] as u16) << 8)) as usize;
                if ext_offset == 0 || ext_offset > entry_size as usize {
                    return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::BadFormat);
                }
                item.short_name = String::from_utf8_lossy(&node_value[14..ext_offset - 1]).to_string();
                if let Some(pos) = item.short_name.find('\0') {
                    item.short_name.truncate(pos);
                }
    
                let ext_size = node_value[ext_offset] as u16 | ((node_value[ext_offset + 1] as u16) << 8);
                if ext_size > entry_size {
                    return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::Other(format!("Error in ext size for path: {:?}", element_route)));
                }
                item.ext_size = ext_size as u32;
    
                let ext_version = node_value[ext_offset + 2] as u16 | ((node_value[ext_offset + 3] as u16) << 8);
                item.ext_version = ext_version as u32;
    
                let mut offset = 4 + ext_offset;
                if ext_version >= 0x03 {
                    let check = u32::from_le_bytes(node_value[offset..offset + 4].try_into().unwrap_or_default()) as u64;
                    if check != 0xbeef0004 {
                        return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::Other(format!("Error parsing file entry detecting 0xbeef0004")));
                    }
                    offset += 4;
                    match dosdate(&node_value[offset..offset + 4]) {
                        Some(v) => {
                            item.c_time = v;
                        },
                        None => {}
                    };
                    offset += 4;
                    match dosdate(&node_value[offset..offset + 4]) {
                        Some(v) => {
                            item.a_time = v;
                        },
                        None => {}
                    };
                    offset += 6; // 2 from unknown
                }
                
                if ext_version >= 0x07 {
                    offset += 18;
                }
                if ext_version >= 0x03 {
                    offset += 2; //Name size
                }
                if ext_version >= 0x09 {
                    offset += 4;
                }
                if ext_version >= 0x08 {
                    offset += 4;
                }
    
                if ext_version >= 0x03 {
                    let str_vec : Vec<u16> = node_value[offset..].chunks(2).map(|v| {
                        if v.len() == 2 {
                            (v[1] as u16) << 8 | v[0] as u16
                        }else if v.len() == 1 {
                            v[0] as u16
                        }else {
                            0
                        }
                    }).collect();
                    let pos = str_vec.iter().position(|&v| v == 0).unwrap_or_default();
                    if pos > 0 {
                        item.long_name = String::from_utf16_lossy(&str_vec[0..pos]);
                    }
                }
                ShellItem::File(item)
            }
        ))
    }
    let is_network = (entry_type & 0x70) == 0x40;
    if is_network {
        return Bitacora::new(Some(
            {
                let mut item = ShellNetworkItem::default();
                if entry_type & 0x0F == 0x0D {
                    if node_value.len() < 20 {
                        return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::BadFormat);
                    }
                    item.guid = Some(Uuid::from_slice_le(&node_value[3..19]).unwrap_or_default().as_u128());
                }else {
                    let flags = node_value[4];
                    item.flags = flags as u32;
                    let mut offset = 5;
                    let pos = node_value[offset..].iter().position(|&v| v == 0).unwrap_or_default();
                    if pos > 0 {
                        item.location = String::from_utf8_lossy(&node_value[offset.. offset + pos]).to_string();
                        offset += pos + 1;
                    }else{
                        return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::BadFormat);
                    }
                    if (flags & 0x80) > 0 {
                        let str_vec = &node_value[offset..];
                        let pos = str_vec.iter().position(|&v| v == 0).unwrap_or_default();
                        if pos > 0 {
                            item.description = String::from_utf8_lossy(&str_vec[0..pos]).to_string();
                            offset += pos + 1;
                        }else{
                            return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::BadFormat);
                        }
                    }
                    if (flags & 0x40) > 0 {
                        let str_vec = &node_value[offset..];
                        let pos = str_vec.iter().position(|&v| v == 0).unwrap_or_default();
                        if pos > 0 {
                            item.comment = String::from_utf8_lossy(&str_vec[0..pos]).to_string();
                        }else{
                            return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::BadFormat);
                        }
                    }
                }
                ShellItem::Network(item)
            }
        ));
    }
    Bitacora::new(Some(match entry_type {
        0x1F => {
            // FOLDER
            let mut item = ShellFolderItem::default();
            if node_value.len() < 20 {
                return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::BadFormat);
            }
            item.id = node_value[3];
            item.guid = Uuid::from_slice_le(&node_value[4..20]).unwrap_or_default().as_u128();
            item.name = match node_value[3] {
                0x00 => "INTERNET_EXPLORER",
                0x42 => "LIBRARIES",
                0x44 => "USERS",
                0x48 => "MY_DOCUMENTS",
                0x50 => "MY_COMPUTER",
                0x58 => "NETWORK",
                0x60 => "RECYCLE_BIN",
                0x68 => "INTERNET_EXPLORER",
                0x70 => "UNKNOWN",
                0x80 => "MY_GAMES",
                _ => ""
            }.into();
            // Name must be retrieved 
            ShellItem::Folder(item)
        },
        0x2f => {
            //VOLUME
            let mut item = ShellVolumeItem::default();
            if node_value.len() < 6 {
                return Bitacora::error(PARSER_NAME, format!("MRU Bag {:?}", element_route), ForensicError::BadFormat);
            }
            item.name = String::from_utf8_lossy(&node_value[3..6]).to_string();
            ShellItem::Volume(item)
        },
        _ => ShellItem::Unknown(entry_type as u32)
    }))


}

pub fn dosdate(data : &[u8]) -> Option<i64> {
    if data.len() != 4 {
        return None;
    }
    let dt = u16::from_le_bytes(data[0..2].try_into().unwrap_or_else(|_| [0,0])) as u64;
    //let dt = ((data[1] as u64) << 8) | data[0] as u64;
    let day = dt & 0b0000000000011111;
    let month = (dt & 0b0000000111100000) >> 5;
    let year = (dt & 0b1111111000000000) >> 9;
    let year = year + 1980;
    let dd = u16::from_le_bytes(data[2..4].try_into().unwrap_or_else(|_| [0,0])) as u64;
    //let dd = ((data[3] as u64) << 8) | data[2] as u64;
    let sec = (dd & 0b0000000000011111) * 2;
    let minute = (dd & 0b0000011111100000) >> 5;
    let hour = (dd & 0b1111100000000000) >> 11;
    if day == 0 || month == 0 {
        return None;
    }
    let dt = Utc.ymd(year as i32, month as u32, day as u32).and_hms(hour as u32, minute as u32, sec as u32);
    //println!("Dosdate: {}, {}, {}-{}-{} {}:{}:{}", dt.timestamp(), dd, year, month, day, hour, minute, sec);
    Some(dt.timestamp())
}
