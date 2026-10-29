use anyhow::{anyhow, Result};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const NODEID_PREFIX: &str = "inf1:";

fn default_allow() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_unknown_allow() -> Vec<String> {
    // TOFU-нодам — только discovery (read-only). Не store (запись в DHT),
    // не pubsub/сервисы. Полное доверие — после pin в конфиге.
    vec![
        "dht.lookup".to_string(),
        "dht.update".to_string(),
        "dht.find_node".to_string(),
        "dht.find_value".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PeerConfig {
    pub name: String,
    pub node_id: String,
    pub ed_pub: String,
    pub x_pub: String,
    pub endpoints: Vec<String>,
    #[serde(default = "default_allow")]
    pub allow: Vec<String>,
    /// лимит запросов/сек от этого пира (0 = без лимита)
    #[serde(default)]
    pub rate_limit_per_sec: u32,
    /// роль (RBAC): раскрывается в allow-список через roles ноды
    #[serde(default)]
    pub role: Option<String>,
    /// роль хранения пира: ["mail"] / ["files"] / обе (пусто = все бакеты)
    #[serde(default)]
    pub storage_roles: Vec<String>,
}

impl PeerConfig {
    /// allow-список с учётом роли (role раскрывается через roles).
    pub fn effective_allow(&self, roles: &HashMap<String, Vec<String>>) -> Vec<String> {
        let mut out = self.allow.clone();
        if let Some(role) = &self.role {
            if let Some(list) = roles.get(role) {
                for a in list {
                    if !out.contains(a) {
                        out.push(a.clone());
                    }
                }
            }
        }
        out
    }

    pub fn node_id_raw(&self) -> Result<[u8; 20]> {
        let s = self
            .node_id
            .strip_prefix(NODEID_PREFIX)
            .unwrap_or(&self.node_id);
        let b = hex::decode(s)?;
        b.try_into().map_err(|_| anyhow!("node_id должен быть 20 байт"))
    }

    pub fn ed_bytes(&self) -> Result<[u8; 32]> {
        let b = hex::decode(&self.ed_pub)?;
        b.try_into().map_err(|_| anyhow!("ed_pub должен быть 32 байта"))
    }

    pub fn x_bytes(&self) -> Result<[u8; 32]> {
        let b = hex::decode(&self.x_pub)?;
        b.try_into().map_err(|_| anyhow!("x_pub должен быть 32 байта"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NodeConfig {
    pub name: String,
    pub listen: String,
    /// порт исходящего QUIC-сокета (для NAT hole punching — фиксированный = стабильный
    /// публичный адрес через NAT); пусто = эфемерный
    #[serde(default)]
    pub client_listen: Option<String>,
    #[serde(default)]
    pub advertise: Option<String>,
    pub peers: Vec<PeerConfig>,
    /// принимать неизвестные ноды (TOFU, как SSH): они получают ACL из unknown-allow
    #[serde(default)]
    pub allow_unknown: bool,
    /// ACL для неизвестных нод
    #[serde(default = "default_unknown_allow")]
    pub unknown_allow: Vec<String>,
    /// HTTP-эндпоинт Prometheus-метрик (напр. "127.0.0.1:9401"); пусто = выкл
    #[serde(default)]
    pub metrics_listen: Option<String>,
    /// уровень логов: 0=error, 1=warn, 2=info, 3=debug
    #[serde(default)]
    pub log_level: Option<u8>,
    /// роли (RBAC): имя роли -> allow-список
    #[serde(default)]
    pub roles: HashMap<String, Vec<String>>,
    /// TTL (сек) для сообщений в outbox (retention, GDPR)
    #[serde(default = "default_outbox_ttl")]
    pub outbox_ttl_secs: u64,
    /// роль хранения: ["mail"] / ["files"] / обе (пусто = все бакеты).
    /// Нода может быть только почтовым или только файловым хранилищем, или и тем и тем.
    #[serde(default)]
    pub storage_roles: Vec<String>,
    /// Доверенные валидаторы (для будущего консенсуса PoA): node_id каждой ноды-валидатора.
    /// Сейчас один валидатор (владелец); когда появится блокчейн-слой, эти ноды будут
    /// подписывать блоки (кворум). Пусто = консенсус не активен (текущий режим).
    #[serde(default)]
    pub validators: Vec<String>,
    /// Домен сети (федерация), напр. "infmail.org". Используется для подтверждения валидатора
    /// через DNS TXT: нода проверяет, что TXT-запись домена содержит node_id валидатора.
    /// Позволяет федерации: каждый владелец своего домена может поднять свою сеть.
    #[serde(default)]
    pub domain: Option<String>,
    /// HTTP-слушатель веб-API и webmail (напр. "0.0.0.0:3000"); пусто = выкл
    #[serde(default)]
    pub web_listen: Option<String>,
    /// TON-кошелёк владельца ноды (для выплат наград). Указывается при init ноды.
    #[serde(default)]
    pub wallet: Option<String>,
    /// каталог со статикой фронтенда (сборка Next.js); пусто = без статики
    #[serde(default)]
    pub web_static: Option<String>,
}

fn default_outbox_ttl() -> u64 {
    3600
}

pub fn load(path: &Path) -> Result<NodeConfig> {
    let raw = std::fs::read_to_string(path).map_err(|e| anyhow!("config: {e}"))?;
    serde_yaml::from_str(&raw).map_err(|e| anyhow!("yaml: {e}"))
}

pub fn save(path: &Path, cfg: &NodeConfig) -> Result<()> {
    std::fs::write(path, serde_yaml::to_string(cfg)?)?;
    Ok(())
}
