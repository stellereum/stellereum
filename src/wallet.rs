//! Lightweight Wallet Module for Stellereum (SPV & Light Client)
//! Handles key derivation, 12-word mnemonic seed generation, password-encrypted keystore
//! with Argon2 + ChaCha20Poly1305, SPV Merkle inclusion proof verification,
//! and native transaction creation (standard, confidential, AI session delegation, and CLOB trades).

use crate::cell::{CellHash, MerkleProof, PatriciaTrie};
use crate::crypto_privacy::{ConfidentialTransfer, PedersenCommitment, StealthAddress, ViewingKey};
use crate::sharding::Transaction;
use crate::zkml::SessionKeyAuthorization;
use aead::{Aead, KeyInit};
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Default location for Stellereum wallet directory
pub fn default_wallet_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".stellereum")
}

pub fn default_wallet_path() -> PathBuf {
    default_wallet_dir().join("wallet.json")
}

// ============================================================================
// Epoch-seal wallet helpers (the WALLET side of the MEV protection)
// ============================================================================

/// Seal an already-signed transaction to an MEV epoch public key.
///
/// This is what "a wallet ENCRYPTS to the epoch public key" means in code:
/// the transaction is serialized, hashed, and sealed with
/// [`crate::mev_epoch::seal_transaction`]. Only the returned envelope (the
/// ciphertext plus the transparent ordering metadata) ever leaves the
/// wallet — the plaintext transaction is kept locally and never published.
///
/// Fail-closed: an envelope whose key is not a valid curve point, or whose
/// serialization fails, is refused here — a wallet must never submit a seal
/// nobody can open.
///
/// The caller MUST have checked the key against the chain first (compare
/// `epoch_key.commitment()` with the `epoch_key_commitment` of a VERIFIED
/// block of that epoch — see
/// [`crate::light_client::verify_epoch_key_against_block`]). Sealing to a
/// key the network never committed to produces a transaction that can never
/// be included, and the sender still pays the drop bond.
pub fn seal_transaction_for_epoch(
    epoch_key: &crate::mev_epoch::EpochPublicKey,
    tx: &Transaction,
) -> Result<crate::mev_epoch::SealedEnvelope, String> {
    let plaintext = bincode::serialize(tx)
        .map_err(|e| format!("seal: transaction serialization failed: {e}"))?;
    let tx_hash = tx.compute_tx_hash();
    let meta = crate::mev_epoch::TransparentMeta::for_transaction(tx);
    crate::mev_epoch::seal_transaction(epoch_key, &plaintext, tx_hash, meta)
}

/// Encode a sealed envelope as the hex wire payload for
/// `stell_sendSealedTransaction`.
///
/// The encoding is the gossip wire frame (`MAGIC || bincode(envelope)`),
/// hex-wrapped for the JSON-RPC `payload` parameter. The bytes carry the
/// CIPHERTEXT only: assert this in your own integration test by checking
/// the serialized transaction bytes do not appear in the payload.
pub fn encode_sealed_for_submit(
    envelope: &crate::mev_epoch::SealedEnvelope,
) -> Result<String, String> {
    let bytes = crate::mev_epoch::encode_sealed_payload(envelope)?;
    Ok(hex::encode(bytes))
}

/// Compact built-in mnemonic wordlist (1024 distinct standard words)
pub const WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst",
    "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
    "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear",
    "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt",
    "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome",
    "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony",
    "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin",
    "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter",
    "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
    "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
    "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash",
    "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught",
    "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal",
    "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon",
    "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean",
    "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog",
    "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast",
    "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress",
    "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
    "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin",
    "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl",
    "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
    "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry",
    "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve",
    "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring",
    "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide",
    "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
    "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit",
    "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy",
    "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary",
    "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
    "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display",
    "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip",
    "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty",
    "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy",
    "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
    "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else",
    "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable",
    "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine",
    "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire",
    "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error",
    "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse",
    "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand",
    "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow",
    "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family",
    "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
    "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file",
    "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first",
    "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee",
    "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam",
    "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork",
    "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame",
    "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit",
    "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery",
    "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate",
    "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown",
    "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid",
    "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health",
    "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden",
    "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday",
    "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry",
    "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify",
    "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune",
    "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index",
    "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit",
    "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
    "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite",
    "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar",
    "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge",
    "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
    "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten",
    "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake",
    "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left",
    "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson",
    "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like",
    "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan",
    "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge",
    "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine",
    "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine",
    "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix",
    "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media",
    "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry",
    "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed",
    "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster",
    "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor",
    "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum",
    "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect",
    "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next",
    "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable",
    "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak",
    "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic",
    "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose",
    "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original",
    "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
    "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace",
    "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot",
    "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment",
    "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people",
    "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
    "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer",
    "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please",
    "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police",
    "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato",
    "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison",
    "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote",
    "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull",
    "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose",
    "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question",
    "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio",
    "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate",
    "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall",
    "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region",
    "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember",
    "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace",
    "report", "require", "rescue", "resemble", "resist", "resource", "response", "result",
    "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple",
    "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance",
    "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
    "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail",
    "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi",
    "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme",
    "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub",
    "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek",
    "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service",
    "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell",
    "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop",
    "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since",
    "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin",
    "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim",
    "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack",
    "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar",
    "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul",
    "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
    "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square",
    "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand",
    "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still",
    "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit",
    "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun",
    "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise",
    "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear",
    "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system",
    "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste",
    "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test",
    "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this",
    "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt",
    "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today",
    "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue",
    "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss",
    "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial",
    "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly",
    "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey",
    "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
    "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair",
    "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until",
    "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge",
    "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague",
    "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
    "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel",
    "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage",
    "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice",
    "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall",
    "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
    "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird",
    "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip",
    "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink",
    "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder",
    "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist",
    "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone",
    "zoo",
];

/// 24-Word Standard Mnemonic Phrase Generator and Decoder
pub struct Mnemonic;

impl Mnemonic {
    /// Generate a 24-word standard BIP-39 mnemonic phrase and derived 32-byte master seed
    pub fn generate() -> (String, [u8; 32]) {
        let mut entropy = [0u8; 32]; // 256 bits = 24 words of 11 bits each (256 + 8 checksum)
        OsRng.fill_bytes(&mut entropy);

        let hash = Sha256::digest(entropy);
        let checksum = hash[0]; // 8 bits of checksum

        let mut bits = Vec::with_capacity(264);
        for b in entropy {
            for i in (0..8).rev() {
                bits.push((b >> i) & 1);
            }
        }
        for i in (0..8).rev() {
            bits.push((checksum >> i) & 1);
        }

        let mut words = Vec::with_capacity(24);
        for chunk in bits.chunks(11).take(24) {
            let mut idx = 0usize;
            for &bit in chunk {
                idx = (idx << 1) | (bit as usize);
            }
            let word = WORDLIST[idx % WORDLIST.len()];
            words.push(word);
        }

        let phrase = words.join(" ");
        let seed = Self::derive_seed(&phrase);
        (phrase, seed)
    }

    /// Restore 32-byte seed from a mnemonic phrase (accepts 24 words or legacy 12 words)
    pub fn from_phrase(phrase: &str) -> Result<[u8; 32], String> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        if words.len() != 24 && words.len() != 12 {
            return Err("Mnemonic must contain exactly 24 words (or legacy 12 words)".to_string());
        }
        for w in &words {
            if !WORDLIST.contains(w) {
                return Err(format!(
                    "Word '{}' is not in the standard mnemonic dictionary",
                    w
                ));
            }
        }

        if words.len() == 24 {
            let mut bits = Vec::with_capacity(264);
            for w in &words {
                let idx = WORDLIST.iter().position(|x| x == w).unwrap();
                for i in (0..11).rev() {
                    bits.push((idx >> i) & 1);
                }
            }

            let mut ent_bytes = [0u8; 32];
            for i in 0..32 {
                let mut byte = 0u8;
                for j in 0..8 {
                    byte = (byte << 1) | (bits[i * 8 + j] as u8);
                }
                ent_bytes[i] = byte;
            }

            let mut chk_byte = 0u8;
            for j in 0..8 {
                chk_byte = (chk_byte << 1) | (bits[256 + j] as u8);
            }

            let expected_chk = Sha256::digest(ent_bytes)[0];
            if chk_byte != expected_chk {
                return Err(
                    "Mnemonic checksum validation failed. Please check the spelling of your words."
                        .to_string(),
                );
            }
        }

        Ok(Self::derive_seed(phrase))
    }

    fn derive_seed(phrase: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"STELLEREUM_MNEMONIC_SALT_V1");
        hasher.update(phrase.trim().as_bytes());
        let h1 = hasher.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(h1);
        hasher2.update(b"STELLEREUM_DERIVATION_KEY");
        hasher2.finalize().into()
    }
}

/// Hardened Argon2id parameters (64 MiB, 3 passes, 4 lanes) used for the
/// library keystore. Matches the CLI's `HardenedKeystore` so both paths are
/// equally expensive to brute-force.
fn hardened_argon2() -> Argon2<'static> {
    let params = argon2::Params::new(65536, 3, 4, Some(32)).expect("valid Argon2 params");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

/// Password-Encrypted Keystore File
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keystore {
    pub version: u32,
    pub address_hex: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

impl Keystore {
    /// Encrypt master private key with Argon2id + ChaCha20Poly1305
    pub fn encrypt(
        secret_key: &[u8; 32],
        address_hex: &str,
        password: &str,
    ) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // Derive 32-byte symmetric key via memory-hard Argon2id
        let mut derived_key = [0u8; 32];
        let argon2 = hardened_argon2();
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| format!("Argon2 KDF failed: {:?}", e))?;

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let xnonce = XNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(xnonce, secret_key.as_ref())
            .map_err(|e| format!("Encryption error: {:?}", e))?;

        Ok(Self {
            version: 1,
            address_hex: address_hex.to_string(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        })
    }

    /// Decrypt master private key
    pub fn decrypt(&self, password: &str) -> Result<[u8; 32], String> {
        let salt = hex::decode(&self.salt_hex).map_err(|e| format!("Invalid salt hex: {e}"))?;
        let nonce = hex::decode(&self.nonce_hex).map_err(|e| format!("Invalid nonce hex: {e}"))?;
        let ciphertext = hex::decode(&self.ciphertext_hex)
            .map_err(|e| format!("Invalid ciphertext hex: {e}"))?;

        let mut derived_key = [0u8; 32];
        let argon2 = hardened_argon2();
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| format!("Argon2 KDF failed: {:?}", e))?;

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let xnonce = XNonce::from_slice(&nonce);

        let decrypted = cipher
            .decrypt(xnonce, ciphertext.as_ref())
            .map_err(|_| "Incorrect password or corrupted keystore".to_string())?;

        if decrypted.len() != 32 {
            return Err("Decrypted key length mismatch".to_string());
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Ok(key)
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create directory: {e}"))?;
            }
        }
        let json =
            serde_json::to_string_pretty(self).map_err(|e| format!("Json serialize error: {e}"))?;
        fs::write(path, json).map_err(|e| format!("Failed to write keystore file: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Failed to set keystore permissions: {e}"))?;
        }
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        assert_owner_only_perms(path)?;
        let json = fs::read_to_string(path).map_err(|e| format!("Failed to read keystore: {e}"))?;
        serde_json::from_str(&json).map_err(|e| format!("Corrupted keystore JSON: {e}"))
    }
}

/// Refuse to load a key file that group or others can read (owner-only
/// posture: 0600). Returns `Ok(())` on non-unix platforms.
#[cfg(unix)]
fn assert_owner_only_perms(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path).map_err(|e| format!("Failed to stat key file: {e}"))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "refusing to load group/world-accessible key file {}: set 0600",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_owner_only_perms(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Default scheme for NEW wallet keys: Falcon-512 (PQ-first write).
/// Legacy Ed25519 keys keep loading and signing (dual-read); nothing here
/// changes the Ed25519 wire shape.
pub fn default_wallet_key_scheme() -> crate::post_quantum::PqScheme {
    crate::post_quantum::PqScheme::Falcon512
}

/// In-memory wallet key material: either a post-quantum Falcon-512 keypair
/// (the default for new keys) or a legacy Ed25519 signing key.
///
/// The sign path dispatches on the LOADED key and refuses cross-scheme
/// requests fail-closed ([`Self::sign_transfer_as`]); legacy Ed25519 flows
/// keep their exact historical bytes and verification.
pub enum WalletKeyMaterial {
    Falcon {
        keypair: Box<crate::post_quantum::FalconKeypair>,
    },
    Ed25519 {
        signing_key: Box<SigningKey>,
    },
}

impl Clone for WalletKeyMaterial {
    fn clone(&self) -> Self {
        match self {
            Self::Falcon { keypair } => Self::Falcon {
                keypair: Box::new(
                    crate::post_quantum::FalconKeypair::from_bytes(&keypair.to_bytes())
                        .expect("Falcon keypair round-trips through its byte encoding"),
                ),
            },
            Self::Ed25519 { signing_key } => Self::Ed25519 {
                signing_key: Box::new(SigningKey::from_bytes(&signing_key.to_bytes())),
            },
        }
    }
}

impl std::fmt::Debug for WalletKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletKeyMaterial")
            .field("scheme", &self.scheme().name())
            .field("address", &hex::encode(self.address()))
            .finish()
    }
}

/// On-disk wallet key file (JSON): explicit scheme tag plus hex key bytes.
/// Schemeless fallbacks (raw 32-byte seed, hex seed, raw/hex Falcon blob)
/// are accepted on LOAD for backward compatibility; SAVE always writes this
/// tagged shape (PQ-first-write).
#[derive(Serialize, Deserialize)]
struct WalletKeyFileV1 {
    scheme: String,
    key_hex: String,
}

/// Save wallet key material, creating parent directories. The file is
/// owner-only (0600) on unix.
pub fn save_wallet_key(path: &Path, key: &WalletKeyMaterial) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {e}"))?;
        }
    }
    let file = match key {
        WalletKeyMaterial::Falcon { keypair } => WalletKeyFileV1 {
            scheme: "falcon512".to_string(),
            key_hex: hex::encode(keypair.to_bytes()),
        },
        WalletKeyMaterial::Ed25519 { signing_key } => WalletKeyFileV1 {
            scheme: "ed25519".to_string(),
            key_hex: hex::encode(signing_key.to_bytes()),
        },
    };
    let json =
        serde_json::to_string_pretty(&file).map_err(|e| format!("Json serialize error: {e}"))?;
    fs::write(path, json).map_err(|e| format!("Failed to write key file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set key file permissions: {e}"))?;
    }
    Ok(())
}

/// Load wallet key material with dual-read auto-detect (PQ preferred):
/// tagged JSON first, then schemeless raw/hex with Falcon tried before
/// Ed25519. Unknown schemes, truncated blobs and empty files are refused
/// fail-closed (never guessed, never downgraded). Group/world-readable
/// files are refused on unix.
pub fn load_wallet_key(path: &Path) -> Result<WalletKeyMaterial, String> {
    assert_owner_only_perms(path)?;
    let raw = fs::read(path).map_err(|e| format!("Failed to read key file: {e}"))?;
    if raw.is_empty() {
        return Err("empty key file: refusing to guess".to_string());
    }
    if let Ok(file) = serde_json::from_slice::<WalletKeyFileV1>(&raw) {
        return match file.scheme.to_ascii_lowercase().as_str() {
            "falcon512" | "falcon" | "falcon-512" => {
                let bytes = hex::decode(file.key_hex.trim())
                    .map_err(|e| format!("Invalid Falcon key hex: {e}"))?;
                crate::post_quantum::FalconKeypair::from_bytes(&bytes)
                    .map(|keypair| WalletKeyMaterial::Falcon {
                        keypair: Box::new(keypair),
                    })
                    .ok_or_else(|| {
                        "corrupt Falcon-512 key blob: refusing to downgrade to Ed25519".to_string()
                    })
            }
            "ed25519" | "ed" => {
                let bytes = hex::decode(file.key_hex.trim())
                    .map_err(|e| format!("Invalid Ed25519 key hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err("corrupt Ed25519 key blob: expected 32 bytes".to_string());
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                Ok(WalletKeyMaterial::Ed25519 {
                    signing_key: Box::new(SigningKey::from_bytes(&seed)),
                })
            }
            other => Err(format!(
                "unknown wallet key scheme '{other}': refusing to guess"
            )),
        };
    }
    // Schemeless fallback: hex text decodes to a candidate, otherwise the
    // raw bytes are the candidate. Falcon is tried BEFORE Ed25519 (PQ
    // preferred); a truncated Falcon blob (wrong length for both shapes)
    // is refused, never downgraded.
    let trimmed = String::from_utf8_lossy(&raw);
    let trimmed = trimmed.trim();
    let hex_candidate: Option<Vec<u8>> =
        if !trimmed.is_empty() && trimmed.len().is_multiple_of(2) && is_hex_text(trimmed) {
            hex::decode(trimmed).ok()
        } else {
            None
        };
    if let Some(ref bytes) = hex_candidate {
        if let Some(keypair) = crate::post_quantum::FalconKeypair::from_bytes(bytes) {
            return Ok(WalletKeyMaterial::Falcon {
                keypair: Box::new(keypair),
            });
        }
    }
    if let Some(keypair) = crate::post_quantum::FalconKeypair::from_bytes(&raw) {
        return Ok(WalletKeyMaterial::Falcon {
            keypair: Box::new(keypair),
        });
    }
    if let Some(bytes) = hex_candidate {
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return Ok(WalletKeyMaterial::Ed25519 {
                signing_key: Box::new(SigningKey::from_bytes(&seed)),
            });
        }
    }
    if raw.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        return Ok(WalletKeyMaterial::Ed25519 {
            signing_key: Box::new(SigningKey::from_bytes(&seed)),
        });
    }
    Err("unrecognized key file: refusing to guess (expected tagged JSON, hex seed, raw 32-byte seed, or Falcon blob)".to_string())
}

fn is_hex_text(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_hexdigit())
}

impl WalletKeyMaterial {
    /// New PQ-first key, deterministically derived from a 32-byte seed
    /// (same raw derivation the faucet uses, so test seeds reproduce the
    /// same address; production callers generate the seed with OS entropy).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::Falcon {
            keypair: Box::new(crate::post_quantum::FalconKeypair::generate_from_seed_bytes(seed)),
        }
    }

    /// Legacy Ed25519 key from a 32-byte seed. The address matches the
    /// historical [`WalletAccount::from_seed`] derivation byte-for-byte.
    pub fn ed25519_from_seed(seed: &[u8; 32]) -> Self {
        Self::Ed25519 {
            signing_key: Box::new(SigningKey::from_bytes(seed)),
        }
    }

    /// Which scheme this key signs with.
    pub fn scheme(&self) -> crate::post_quantum::PqScheme {
        match self {
            Self::Falcon { .. } => crate::post_quantum::PqScheme::Falcon512,
            Self::Ed25519 { .. } => crate::post_quantum::PqScheme::Ed25519,
        }
    }

    /// Whether this key provides quantum resistance.
    pub fn is_post_quantum(&self) -> bool {
        self.scheme().is_post_quantum()
    }

    /// The 32-byte account address: zero-salt Falcon derivation for PQ keys,
    /// the verifying key for legacy Ed25519 keys.
    pub fn address(&self) -> [u8; 32] {
        match self {
            Self::Falcon { keypair } => crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &keypair.public_key,
                &crate::post_quantum::DEFAULT_SALT,
            ),
            Self::Ed25519 { signing_key } => signing_key.verifying_key().to_bytes(),
        }
    }

    /// Sign an unbound transfer with this key's own scheme: the PQ faucet
    /// shape (always-explicit PQ1 envelope, no chain binding) for Falcon
    /// keys, the exact legacy ed25519 bytes for Ed25519 keys.
    #[allow(clippy::too_many_arguments)]
    // GATE: transfer signing needs the full tx fields; callers pass them explicitly.
    pub fn sign_transfer(
        &self,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
    ) -> Transaction {
        match self {
            Self::Falcon { keypair } => {
                let probe = Transaction::new_pq_explicit(
                    crate::post_quantum::PqScheme::Falcon512,
                    keypair.public_key.clone(),
                    vec![0u8; crate::post_quantum::FALCON512_SIG_LEN],
                    to,
                    amount,
                    gas_limit,
                    nonce,
                    source_shard,
                    target_shard,
                    Vec::new(),
                    &crate::post_quantum::DEFAULT_SALT,
                );
                let sig = keypair.sign(&probe.signing_message());
                assert!(
                    sig.len() == crate::post_quantum::FALCON512_SIG_LEN,
                    "Falcon-512 signing failed closed"
                );
                Transaction::new_pq_explicit(
                    crate::post_quantum::PqScheme::Falcon512,
                    keypair.public_key.clone(),
                    sig,
                    to,
                    amount,
                    gas_limit,
                    nonce,
                    source_shard,
                    target_shard,
                    Vec::new(),
                    &crate::post_quantum::DEFAULT_SALT,
                )
            }
            Self::Ed25519 { signing_key } => Transaction::sign(
                signing_key,
                to,
                amount,
                gas_limit,
                nonce,
                source_shard,
                target_shard,
            ),
        }
    }

    /// Sign a chain-bound transfer with this key's own scheme (anti
    /// cross-chain replay; strict check passes only on `chain_id`).
    #[allow(clippy::too_many_arguments)]
    // GATE: bound transfer signing needs the full tx fields plus chain id; callers pass them explicitly.
    pub fn sign_bound_transfer(
        &self,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
        chain_id: u64,
    ) -> Transaction {
        match self {
            Self::Falcon { keypair } => {
                let probe = Transaction::new_pq_explicit_with_chain(
                    crate::post_quantum::PqScheme::Falcon512,
                    keypair.public_key.clone(),
                    vec![0u8; crate::post_quantum::FALCON512_SIG_LEN],
                    to,
                    amount,
                    gas_limit,
                    nonce,
                    source_shard,
                    target_shard,
                    Vec::new(),
                    &crate::post_quantum::DEFAULT_SALT,
                    chain_id,
                );
                let sig = keypair.sign(&probe.signing_message());
                assert!(
                    sig.len() == crate::post_quantum::FALCON512_SIG_LEN,
                    "Falcon-512 signing failed closed"
                );
                Transaction::new_pq_explicit_with_chain(
                    crate::post_quantum::PqScheme::Falcon512,
                    keypair.public_key.clone(),
                    sig,
                    to,
                    amount,
                    gas_limit,
                    nonce,
                    source_shard,
                    target_shard,
                    Vec::new(),
                    &crate::post_quantum::DEFAULT_SALT,
                    chain_id,
                )
            }
            Self::Ed25519 { signing_key } => Transaction::sign_with_chain_id(
                signing_key,
                to,
                amount,
                gas_limit,
                nonce,
                source_shard,
                target_shard,
                chain_id,
            ),
        }
    }

    /// Sign a syscall-carrying transfer (self-send, zero native amount) with
    /// this key's own scheme.
    pub fn sign_payload_transfer(
        &self,
        payload: Vec<crate::svm::OpCode>,
        gas_limit: u64,
        nonce: u64,
    ) -> Transaction {
        match self {
            Self::Falcon { keypair } => {
                let from = self.address();
                let probe = Transaction::new_pq_explicit(
                    crate::post_quantum::PqScheme::Falcon512,
                    keypair.public_key.clone(),
                    vec![0u8; crate::post_quantum::FALCON512_SIG_LEN],
                    from,
                    0,
                    gas_limit,
                    nonce,
                    crate::sharding::MASTERCHAIN_SHARD,
                    crate::sharding::MASTERCHAIN_SHARD,
                    payload.clone(),
                    &crate::post_quantum::DEFAULT_SALT,
                );
                let sig = keypair.sign(&probe.signing_message());
                assert!(
                    sig.len() == crate::post_quantum::FALCON512_SIG_LEN,
                    "Falcon-512 signing failed closed"
                );
                Transaction::new_pq_explicit(
                    crate::post_quantum::PqScheme::Falcon512,
                    keypair.public_key.clone(),
                    sig,
                    from,
                    0,
                    gas_limit,
                    nonce,
                    crate::sharding::MASTERCHAIN_SHARD,
                    crate::sharding::MASTERCHAIN_SHARD,
                    payload,
                    &crate::post_quantum::DEFAULT_SALT,
                )
            }
            Self::Ed25519 { signing_key } => {
                let from = signing_key.verifying_key().to_bytes();
                Transaction::sign_with_payload(
                    signing_key,
                    from,
                    0,
                    gas_limit,
                    nonce,
                    crate::sharding::MASTERCHAIN_SHARD,
                    crate::sharding::MASTERCHAIN_SHARD,
                    payload,
                )
            }
        }
    }

    /// Sign a chain-bound syscall-carrying transfer with this key's own scheme.
    pub fn sign_bound_payload_transfer(
        &self,
        payload: Vec<crate::svm::OpCode>,
        gas_limit: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Transaction {
        match self {
            Self::Falcon { keypair } => {
                let from = self.address();
                let probe = Transaction::new_pq_explicit_with_chain(
                    crate::post_quantum::PqScheme::Falcon512,
                    keypair.public_key.clone(),
                    vec![0u8; crate::post_quantum::FALCON512_SIG_LEN],
                    from,
                    0,
                    gas_limit,
                    nonce,
                    crate::sharding::MASTERCHAIN_SHARD,
                    crate::sharding::MASTERCHAIN_SHARD,
                    payload.clone(),
                    &crate::post_quantum::DEFAULT_SALT,
                    chain_id,
                );
                let sig = keypair.sign(&probe.signing_message());
                assert!(
                    sig.len() == crate::post_quantum::FALCON512_SIG_LEN,
                    "Falcon-512 signing failed closed"
                );
                Transaction::new_pq_explicit_with_chain(
                    crate::post_quantum::PqScheme::Falcon512,
                    keypair.public_key.clone(),
                    sig,
                    from,
                    0,
                    gas_limit,
                    nonce,
                    crate::sharding::MASTERCHAIN_SHARD,
                    crate::sharding::MASTERCHAIN_SHARD,
                    payload,
                    &crate::post_quantum::DEFAULT_SALT,
                    chain_id,
                )
            }
            Self::Ed25519 { signing_key } => {
                let from = signing_key.verifying_key().to_bytes();
                Transaction::sign_with_payload_and_chain_id(
                    signing_key,
                    from,
                    0,
                    gas_limit,
                    nonce,
                    crate::sharding::MASTERCHAIN_SHARD,
                    crate::sharding::MASTERCHAIN_SHARD,
                    payload,
                    chain_id,
                )
            }
        }
    }

    /// Scheme-pinned transfer: signs only when `scheme` is this key's own
    /// scheme, otherwise refuses fail-closed (no silent cross-scheme
    /// downgrade or upgrade).
    #[allow(clippy::too_many_arguments)]
    // GATE: pinned transfer signing needs the full tx fields plus scheme; callers pass them explicitly.
    pub fn sign_transfer_as(
        &self,
        scheme: crate::post_quantum::PqScheme,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
    ) -> Result<Transaction, String> {
        if scheme != self.scheme() {
            return Err(format!(
                "wallet key scheme mismatch: key is {} but {} was requested; refusing to cross-sign",
                self.scheme(),
                scheme
            ));
        }
        Ok(self.sign_transfer(to, amount, gas_limit, nonce, source_shard, target_shard))
    }
}

/// Full in-memory active wallet account
pub struct WalletAccount {
    pub signing_key: SigningKey,
    pub address: [u8; 32],
    pub viewing_key: ViewingKey,
    pub spend_priv: Scalar,
    pub spend_pub: [u8; 32],
    pub stealth_address: StealthAddress,
}

impl WalletAccount {
    /// Derive all keys deterministically from a 32-byte master seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let address = signing_key.verifying_key().to_bytes();

        // Deterministic derivation of Viewing Key from master seed
        let mut view_hasher = Sha256::new();
        view_hasher.update(seed);
        view_hasher.update(b"VIEWING_KEY_DERIVE");
        let view_scalar_bytes: [u8; 32] = view_hasher.finalize().into();
        let view_priv = Scalar::from_bytes_mod_order(view_scalar_bytes);
        let view_pub = (RISTRETTO_BASEPOINT_POINT * view_priv)
            .compress()
            .to_bytes();

        let viewing_key = ViewingKey {
            view_priv: view_priv.to_bytes(),
            view_pub,
        };

        // Deterministic derivation of Spend Key from master seed
        let mut spend_hasher = Sha256::new();
        spend_hasher.update(seed);
        spend_hasher.update(b"SPEND_KEY_DERIVE");
        let spend_scalar_bytes: [u8; 32] = spend_hasher.finalize().into();
        let spend_priv = Scalar::from_bytes_mod_order(spend_scalar_bytes);
        let spend_pub = (RISTRETTO_BASEPOINT_POINT * spend_priv)
            .compress()
            .to_bytes();

        let stealth_address = StealthAddress::generate(&view_pub, &spend_pub)
            .expect("Valid Ristretto stealth derivation");

        Self {
            signing_key,
            address,
            viewing_key,
            spend_priv,
            spend_pub,
            stealth_address,
        }
    }

    /// Sign standard transfer with micro-gas
    pub fn create_transaction(
        &self,
        to: [u8; 32],
        amount: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
    ) -> Transaction {
        Transaction::sign(
            &self.signing_key,
            to,
            amount,
            crate::svm::GAS_BASIC_TRANSFER,
            nonce,
            source_shard,
            target_shard,
        )
    }

    /// Sign a standard transfer that carries an EXPLICIT MEMPOOL PRIORITY
    /// BID.
    ///
    /// The bid is the price the mempool orders by first (audit: priority
    /// inversion — `gas_limit` is a resource cap, not a price). It is signed
    /// with the transaction and must be FUNDED: admission requires the
    /// declared `gas_limit` to cover `floor + bid`, so priority is never
    /// free. A bid of 0 is exactly the legacy behaviour.
    ///
    /// `gas_limit` must therefore be raised by at least `priority_fee_per_gas`
    /// above the node's admission floor for the bid to be accepted.
    #[allow(clippy::too_many_arguments)]
    // GATE: wallet tx builder mirrors the on-chain tx fields; callers pass them explicitly.
    pub fn create_transaction_with_priority(
        &self,
        to: [u8; 32],
        amount: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
        gas_limit: u64,
        priority_fee_per_gas: u64,
    ) -> Transaction {
        Transaction::sign_with_priority(
            &self.signing_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            priority_fee_per_gas,
        )
    }

    // ========================================================================
    // Chain-bound constructors (A14 chain-binding rollout, phase 1)
    // ========================================================================
    //
    // The default `create_*` constructors above build UNBOUND (replayable)
    // transactions: the signature covers no chain id, so it verifies on any
    // chain that shares the key. The constructors below are the new wallet
    // DEFAULT: the signature commits `chain_id` (CH1 envelope), so a
    // testnet signature never verifies on mainnet and vice versa. Resolve
    // the id from the node (`LightClient::chain_id`, live-or-default) and
    // pass it explicitly — the wallet never guesses.
    //
    // The unbound constructors stay for offline/legacy use behind the
    // explicit `unbound_legacy_*` hatch, which warns loudly every time it is
    // used. Rollout plan: warn+meter (this wave) -> default-bound wallets ->
    // `require_chain_id` on admission.

    /// Sign a standard transfer BOUND to `chain_id` (anti cross-chain
    /// replay). The wallet default: prefer this over `create_transaction`.
    pub fn create_bound_transaction(
        &self,
        to: [u8; 32],
        amount: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
        chain_id: u64,
    ) -> Transaction {
        Transaction::sign_with_chain_id(
            &self.signing_key,
            to,
            amount,
            crate::svm::GAS_BASIC_TRANSFER,
            nonce,
            source_shard,
            target_shard,
            chain_id,
        )
    }

    /// Build a syscall-carrying transaction BOUND to `chain_id`. `to` is the
    /// sender itself with zero native amount (value moves, if any, inside
    /// the syscall). The wallet default: prefer this over
    /// `create_payload_transaction`.
    pub fn create_bound_payload_transaction(
        &self,
        payload: Vec<crate::svm::OpCode>,
        gas_limit: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Transaction {
        let from = self.signing_key.verifying_key().to_bytes();
        Transaction::sign_with_payload_and_chain_id(
            &self.signing_key,
            from,
            0,
            gas_limit,
            nonce,
            crate::sharding::MASTERCHAIN_SHARD,
            crate::sharding::MASTERCHAIN_SHARD,
            payload,
            chain_id,
        )
    }

    /// Height-gated envelope admissibility for a wallet-built transaction
    /// (PLAN-BINDING phase 3, wallet side of the same predicate consensus
    /// enforces in
    /// [`crate::consensus::verify_transaction_envelope_at_height_with_activation`]).
    ///
    /// Pure: `is_bound` is derived from the envelope itself
    /// (`tx.chain_id().is_some()` covers CH1, session grants, PQ chain
    /// binding and EVM settlement), so the wallet never hand-rolls the
    /// bound/unbound classification. Intended as a submit-time pre-check:
    /// `Ok(())` means the envelope passes the binding gate at
    /// `chain_height`; `Err` carries the stable
    /// [`crate::chain_binding::UNBOUND_REFUSED_ERR_PREFIX`] refusal string
    /// the RPC returns post-activation. Signature validity is NOT checked
    /// here — consensus verifies signatures.
    pub fn check_envelope_binding_at_height(
        tx: &Transaction,
        chain_height: u64,
        activation: &crate::chain_binding::ChainBindingActivation,
        chain_id: u64,
    ) -> Result<(), String> {
        crate::chain_binding::check_admission(
            tx.chain_id().is_some(),
            chain_height,
            activation,
            chain_id,
        )
    }

    /// LEGACY escape hatch: builds the old UNBOUND (replayable) transfer.
    /// Kept for offline signing and backward compatibility ONLY — every use
    /// logs a loud warning, and the rollout plan ends with admission
    /// refusing unbound transactions outright. Prefer
    /// [`Self::create_bound_transaction`].
    pub fn unbound_legacy_transfer(
        &self,
        to: [u8; 32],
        amount: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
    ) -> Transaction {
        tracing::warn!(
            "wallet built an UNBOUND (replayable, no chain id) transaction — \
             prefer create_bound_transaction; unbound admission is metered and will be refused"
        );
        self.create_transaction(to, amount, nonce, source_shard, target_shard)
    }

    /// LEGACY escape hatch: builds the old UNBOUND (replayable)
    /// syscall-carrying transaction. Same warning and same deprecation path
    /// as [`Self::unbound_legacy_transfer`]. Prefer
    /// [`Self::create_bound_payload_transaction`].
    pub fn unbound_legacy_payload_transaction(
        &self,
        payload: Vec<crate::svm::OpCode>,
        gas_limit: u64,
        nonce: u64,
    ) -> Transaction {
        tracing::warn!(
            "wallet built an UNBOUND (replayable, no chain id) payload transaction — \
             prefer create_bound_payload_transaction; unbound admission is metered and will be refused"
        );
        self.create_payload_transaction(payload, gas_limit, nonce)
    }

    /// Create, sign AND seal a standard transfer in one step (the WALLET side
    /// of the epoch seal).
    ///
    /// Fetches nothing: the caller passes the epoch public key it parsed
    /// from `stell_epochKey` (see
    /// [`crate::mev_epoch::EpochPublicKey::from_rpc_json`]). Returns the
    /// signed transaction (kept locally, never published), the sealed
    /// envelope, and the hex wire payload to POST as
    /// `stell_sendSealedTransaction { payload }`.
    ///
    /// Before sealing anything of value, check the key against the chain
    /// (see [`crate::light_client::verify_epoch_key_against_block`]): a key
    /// no block committed to is a key nobody can unseal.
    #[allow(clippy::too_many_arguments)]
    // GATE: sealed-tx builder mirrors the on-chain tx fields plus seal material; callers pass them explicitly.
    pub fn create_sealed_transaction(
        &self,
        to: [u8; 32],
        amount: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
        gas_limit: u64,
        priority_fee_per_gas: u64,
        epoch_key: &crate::mev_epoch::EpochPublicKey,
    ) -> Result<(Transaction, crate::mev_epoch::SealedEnvelope, String), String> {
        let tx = self.create_transaction_with_priority(
            to,
            amount,
            nonce,
            source_shard,
            target_shard,
            gas_limit,
            priority_fee_per_gas,
        );
        let envelope = seal_transaction_for_epoch(epoch_key, &tx)?;
        let payload_hex = encode_sealed_for_submit(&envelope)?;
        Ok((tx, envelope, payload_hex))
    }

    /// Build a syscall-carrying transaction (staking, rotation, ...): `to` is
    /// the sender itself with zero native amount (value moves, if any, inside
    /// the syscall, e.g. the bond into the staking pool). Gas must cover the
    /// opcodes; the caller picks the right `GAS_*` constant.
    pub fn create_payload_transaction(
        &self,
        payload: Vec<crate::svm::OpCode>,
        gas_limit: u64,
        nonce: u64,
    ) -> Transaction {
        let from = self.signing_key.verifying_key().to_bytes();
        Transaction::sign_with_payload(
            &self.signing_key,
            from,
            0,
            gas_limit,
            nonce,
            crate::sharding::MASTERCHAIN_SHARD,
            crate::sharding::MASTERCHAIN_SHARD,
            payload,
        )
    }

    /// Create confidential transfer with Pedersen commitments.
    ///
    /// Thin wrapper over [`Self::build_confidential_transfer`]: the blinding
    /// conservation (`r_out == r_in`, so `C_in - C_out == fee*G` exactly) is
    /// the shared builder path every shielded entry point reuses — including
    /// the first-class RPC path (`stell_shieldedTransfer`), which calls the
    /// associated function directly because a prepare-only endpoint holds no
    /// signing key.
    pub fn create_confidential_transfer(
        &self,
        amount: u64,
        fee: u64,
    ) -> (ConfidentialTransfer, Scalar) {
        Self::build_confidential_transfer(amount, fee)
    }

    /// Build a one-in/one-out confidential transfer with Pedersen commitments.
    ///
    /// THE shared builder (no key needed): input commits to `amount + fee`,
    /// output commits to `amount`, both under the SAME blinding, so the group
    /// equation holds exactly. Returns the transfer plus the output blinding
    /// (== the input blinding) for the wallet's shielded inventory. Range
    /// proofs are NOT built here — the execution path needs them, the caller
    /// attaches them with [`crate::crypto_privacy::RangeProof::prove_auto`].
    pub fn build_confidential_transfer(amount: u64, fee: u64) -> (ConfidentialTransfer, Scalar) {
        // Checked (audit follow-up): amount+fee overflowed silently here.
        let total = amount
            .checked_add(fee)
            .expect("confidential amount+fee overflows");
        let r_in = PedersenCommitment::random_blinding();
        let c_in = PedersenCommitment::commit(total, &r_in);

        // Blinding conservation: r_out = r_in
        let r_out = r_in;
        let c_out = PedersenCommitment::commit(amount, &r_out);

        let transfer = ConfidentialTransfer::new(vec![c_in], vec![c_out], fee);
        (transfer, r_out)
    }

    /// Delegate session key for AI bots with gas spending cap and time validity.
    ///
    /// `scope` is the operation bitmask (`zkml::SCOPE_*`), `max_value_per_tx`
    /// caps the native amount of any single transaction, and `chain_id` binds
    /// the grant to the chain it was minted for (part of the master's signed
    /// message, domain-separated with `STELL_SESSKEY_V1`).
    pub fn delegate_bot_session(
        &self,
        session_pub: [u8; 32],
        max_gas: u64,
        duration_secs: u64,
        scope: u64,
        max_value_per_tx: u64,
        chain_id: u64,
    ) -> SessionKeyAuthorization {
        let valid_until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + duration_secs;

        SessionKeyAuthorization::sign_delegation(
            &self.signing_key,
            session_pub,
            valid_until,
            max_gas,
            scope,
            max_value_per_tx,
            chain_id,
        )
    }

    /// SPV Light Verification: cryptographically verify account balance against Patricia BoC State Root.
    /// Seamlessly verifies both unpinned (16B legacy/dormant) and pinned (49B post-quantum) leaves.
    pub fn verify_spv_balance(
        &self,
        expected_balance: u64,
        expected_nonce: u64,
        state_root: &CellHash,
        merkle_proof: &MerkleProof,
    ) -> bool {
        // 1. Unpinned / dormant 16-byte leaf (balance || nonce)
        let mut expected_bytes = Vec::with_capacity(crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
        expected_bytes.extend_from_slice(&expected_balance.to_be_bytes());
        expected_bytes.extend_from_slice(&expected_nonce.to_be_bytes());

        if PatriciaTrie::verify_merkle_proof(
            state_root,
            &self.address,
            &expected_bytes,
            merkle_proof,
        ) {
            return true;
        }

        // 2. Pinned 49-byte leaf with wallet's native Ed25519 public key hash
        let ed_pk_hash = blake3::hash(&self.address);
        let mut ed_pq_bytes = Vec::with_capacity(crate::cpat2::ACCOUNT_LEAF_LEN_PQ);
        ed_pq_bytes.extend_from_slice(&expected_bytes);
        ed_pq_bytes.push(crate::post_quantum::PqScheme::Ed25519.id());
        ed_pq_bytes.extend_from_slice(ed_pk_hash.as_bytes());

        if PatriciaTrie::verify_merkle_proof(state_root, &self.address, &ed_pq_bytes, merkle_proof)
        {
            return true;
        }

        // 3. Pinned 49-byte leaf with public key registered in global implicit registry
        if let Some((scheme, pk)) =
            crate::sharding::global_implicit_key_registry().lookup(&self.address)
        {
            let pk_hash = blake3::hash(&pk);
            let mut reg_pq_bytes = Vec::with_capacity(crate::cpat2::ACCOUNT_LEAF_LEN_PQ);
            reg_pq_bytes.extend_from_slice(&expected_bytes);
            reg_pq_bytes.push(scheme.id());
            reg_pq_bytes.extend_from_slice(pk_hash.as_bytes());

            if PatriciaTrie::verify_merkle_proof(
                state_root,
                &self.address,
                &reg_pq_bytes,
                merkle_proof,
            ) {
                return true;
            }
        }

        // 4. Pinned 49-byte leaf where pubkey_hash is direct address bytes
        let mut direct_pq_bytes = Vec::with_capacity(crate::cpat2::ACCOUNT_LEAF_LEN_PQ);
        direct_pq_bytes.extend_from_slice(&expected_bytes);
        direct_pq_bytes.push(crate::post_quantum::PqScheme::Ed25519.id());
        direct_pq_bytes.extend_from_slice(&self.address);

        if PatriciaTrie::verify_merkle_proof(
            state_root,
            &self.address,
            &direct_pq_bytes,
            merkle_proof,
        ) {
            return true;
        }

        false
    }

    /// Post-Quantum SPV Light Verification: seamlessly verifies both unpinned (16B)
    /// and pinned (49B) account leaves.
    pub fn verify_spv_balance_pq(
        &self,
        expected_balance: u64,
        expected_nonce: u64,
        state_root: &CellHash,
        merkle_proof: &MerkleProof,
    ) -> bool {
        self.verify_spv_balance(expected_balance, expected_nonce, state_root, merkle_proof)
    }

    /// SPV Light Verification with explicit post-quantum scheme and pubkey hash.
    /// Seamlessly verifies explicit 49-byte pinned leaves and falls back to 16-byte unpinned.
    pub fn verify_spv_balance_explicit_pq(
        &self,
        expected_balance: u64,
        expected_nonce: u64,
        scheme: u8,
        pubkey_hash: &[u8; 32],
        state_root: &CellHash,
        merkle_proof: &MerkleProof,
    ) -> bool {
        let mut expected_bytes = Vec::with_capacity(crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
        expected_bytes.extend_from_slice(&expected_balance.to_be_bytes());
        expected_bytes.extend_from_slice(&expected_nonce.to_be_bytes());

        let mut pq_bytes = Vec::with_capacity(crate::cpat2::ACCOUNT_LEAF_LEN_PQ);
        pq_bytes.extend_from_slice(&expected_bytes);
        pq_bytes.push(scheme);
        pq_bytes.extend_from_slice(pubkey_hash);

        if PatriciaTrie::verify_merkle_proof(state_root, &self.address, &pq_bytes, merkle_proof) {
            return true;
        }

        self.verify_spv_balance(expected_balance, expected_nonce, state_root, merkle_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpat2::AccountLeaf;
    use crate::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};

    #[test]
    fn test_wallet_spv_balance_verification_unpinned_and_pinned() {
        let wallet = WalletAccount::from_seed(&[0x42u8; 32]);
        let address = wallet.address;

        // 1. Unpinned 16-byte leaf
        let unpinned_leaf = AccountLeaf::new_unpinned(5_000, 1).encode();
        assert_eq!(unpinned_leaf.len(), 16);

        let mut trie_unpinned = PatriciaTrie::new();
        trie_unpinned.insert(&address, &unpinned_leaf);
        let root_unpinned = trie_unpinned.root_hash();
        let proof_unpinned = trie_unpinned
            .generate_merkle_proof(&address)
            .expect("proof");

        // Both methods verify unpinned leaf seamlessly
        assert!(wallet.verify_spv_balance(5_000, 1, &root_unpinned, &proof_unpinned));
        assert!(wallet.verify_spv_balance_pq(5_000, 1, &root_unpinned, &proof_unpinned));

        // Wrong balance fails
        assert!(!wallet.verify_spv_balance(9_999, 1, &root_unpinned, &proof_unpinned));
        assert!(!wallet.verify_spv_balance_pq(9_999, 1, &root_unpinned, &proof_unpinned));

        // 2. Pinned 49-byte leaf (Ed25519 scheme with blake3 pubkey hash)
        let pk_hash = blake3::hash(&address);
        let pinned_leaf =
            AccountLeaf::new_pinned(15_000, 4, PqScheme::Ed25519.id(), *pk_hash.as_bytes())
                .encode();
        assert_eq!(pinned_leaf.len(), 49);

        let mut trie_pinned = PatriciaTrie::new();
        trie_pinned.insert(&address, &pinned_leaf);
        let root_pinned = trie_pinned.root_hash();
        let proof_pinned = trie_pinned.generate_merkle_proof(&address).expect("proof");

        // Both methods verify pinned leaf seamlessly
        assert!(wallet.verify_spv_balance(15_000, 4, &root_pinned, &proof_pinned));
        assert!(wallet.verify_spv_balance_pq(15_000, 4, &root_pinned, &proof_pinned));

        // 3. Pinned 49-byte leaf via implicit registry for a PQ-addressed wallet
        let falcon_pk = Transaction::sample_falcon512_pubkey(0x88);
        let pq_address = derive_pq_address(PqScheme::Falcon512, &falcon_pk, &DEFAULT_SALT);
        let mut pq_wallet = WalletAccount::from_seed(&[0x43u8; 32]);
        pq_wallet.address = pq_address;

        crate::sharding::global_implicit_key_registry()
            .register(pq_address, PqScheme::Falcon512, &falcon_pk, &DEFAULT_SALT)
            .expect("register falcon key");

        let falcon_pk_hash = blake3::hash(&falcon_pk);
        let falcon_pinned_leaf = AccountLeaf::new_pinned(
            25_000,
            7,
            PqScheme::Falcon512.id(),
            *falcon_pk_hash.as_bytes(),
        )
        .encode();
        assert_eq!(falcon_pinned_leaf.len(), 49);

        let mut trie_falcon = PatriciaTrie::new();
        trie_falcon.insert(&pq_address, &falcon_pinned_leaf);
        let root_falcon = trie_falcon.root_hash();
        let proof_falcon = trie_falcon
            .generate_merkle_proof(&pq_address)
            .expect("proof");

        assert!(pq_wallet.verify_spv_balance(25_000, 7, &root_falcon, &proof_falcon));
        assert!(pq_wallet.verify_spv_balance_pq(25_000, 7, &root_falcon, &proof_falcon));
        assert!(pq_wallet.verify_spv_balance_explicit_pq(
            25_000,
            7,
            PqScheme::Falcon512.id(),
            falcon_pk_hash.as_bytes(),
            &root_falcon,
            &proof_falcon
        ));
    }

    /// A test-only epoch public key: the wallet helper needs a VALID curve
    /// point, not a real committee key (a real key needs the DKG, which the
    /// `mev_epoch` tests already cover end to end).
    fn test_epoch_key(epoch: u64) -> crate::mev_epoch::EpochPublicKey {
        let point = (RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64))
            .compress()
            .to_bytes();
        crate::mev_epoch::EpochPublicKey {
            epoch,
            public_key: point,
            committee_hash: [0xABu8; 32],
            threshold: 2,
        }
    }

    /// THE WALLET SEALS TO THE EPOCH KEY: the envelope carries the
    /// ciphertext and the transparent metadata, and the wire payload never
    /// contains the plaintext.
    #[test]
    fn seal_for_epoch_hides_the_plaintext_on_the_wire() {
        let wallet = WalletAccount::from_seed(&[0x42u8; 32]);
        let key = test_epoch_key(0);
        let tx = wallet.create_transaction_with_priority([0x99u8; 32], 1_000, 5, 0, 0, 10_000, 25);
        let plaintext = bincode::serialize(&tx).expect("the tx serializes");

        let envelope = seal_transaction_for_epoch(&key, &tx).expect("sealing succeeds");
        assert_eq!(envelope.epoch, 0);
        assert_eq!(envelope.tx_hash, tx.compute_tx_hash());
        // The metadata is the transaction's own fields — nothing hand-rolled.
        let meta = crate::mev_epoch::TransparentMeta::for_transaction(&tx);
        assert_eq!(envelope.meta, meta);
        assert_eq!(envelope.meta.from, wallet.address);
        assert_eq!(envelope.meta.nonce, 5);

        // The SUBMIT payload (what `stell_sendSealedTransaction` takes, and
        // what the gossip carries) never contains the plaintext.
        let payload_hex = encode_sealed_for_submit(&envelope).expect("the payload encodes");
        let payload = hex::decode(&payload_hex).expect("the payload is hex");
        assert!(
            crate::mev_epoch::is_sealed_payload(&payload),
            "the submit payload is a sealed frame"
        );
        assert!(
            !payload
                .windows(plaintext.len())
                .any(|w| w == plaintext.as_slice()),
            "the wire payload must not contain the plaintext transaction"
        );
        // ... and the envelope round-trips through the admission decoder.
        let decoded = crate::mev_epoch::decode_sealed_payload(&payload).expect("decodes");
        assert_eq!(decoded, envelope);
    }

    /// The one-step wallet helper signs, seals and encodes in one call.
    #[test]
    fn create_sealed_transaction_signs_seals_and_encodes() {
        let wallet = WalletAccount::from_seed(&[0x43u8; 32]);
        let key = test_epoch_key(3);
        let (tx, envelope, payload_hex) = wallet
            .create_sealed_transaction([0x11u8; 32], 500, 0, 0, 0, 10_000, 0, &key)
            .expect("one-step seal succeeds");
        assert_eq!(tx.to, [0x11u8; 32]);
        assert_eq!(envelope.tx_hash, tx.compute_tx_hash());
        let payload = hex::decode(&payload_hex).expect("hex");
        let decoded = crate::mev_epoch::decode_sealed_payload(&payload).expect("decodes");
        assert_eq!(decoded.tx_hash, tx.compute_tx_hash());
    }

    /// A key that is not a curve point is refused at SEAL time, not at
    /// submit time: the wallet must never produce a seal nobody can open.
    #[test]
    fn seal_for_epoch_refuses_a_non_point_key() {
        let wallet = WalletAccount::from_seed(&[0x44u8; 32]);
        let mut key = test_epoch_key(0);
        key.public_key = [0xFFu8; 32];
        let tx = wallet.create_transaction([0x11u8; 32], 1, 0, 0, 0);
        assert!(
            seal_transaction_for_epoch(&key, &tx).is_err(),
            "a non-point epoch key must be refused"
        );
    }

    // ====================================================================
    // A14 chain binding: the wallet defaults to BOUND envelopes.
    // ====================================================================

    const TEST_CHAIN_ID: u64 = 5757;
    const OTHER_CHAIN_ID: u64 = 9999;

    /// The bound constructors produce chain-bound transactions that verify
    /// on their own chain and fail a strict check on any other chain.
    #[test]
    fn bound_constructors_bind_the_chain_id() {
        let wallet = WalletAccount::from_seed(&[0x50u8; 32]);
        let tx = wallet.create_bound_transaction([0x99u8; 32], 1_000, 5, 0, 0, TEST_CHAIN_ID);
        assert!(
            tx.is_chain_id_bound(),
            "the default transfer must carry CH1"
        );
        assert_eq!(tx.chain_id(), Some(TEST_CHAIN_ID));
        assert!(tx.verify_signature(), "a bound transaction must verify");
        assert!(
            tx.verify_signature_for_chain(TEST_CHAIN_ID, true),
            "strict check passes on the bound chain"
        );
        assert!(
            !tx.verify_signature_for_chain(OTHER_CHAIN_ID, true),
            "a testnet signature must never verify on another chain"
        );

        let payload = vec![crate::svm::OpCode::Nop, crate::svm::OpCode::Pop];
        let ptx = wallet.create_bound_payload_transaction(payload, 100_000, 6, TEST_CHAIN_ID);
        assert!(
            ptx.is_chain_id_bound(),
            "the default payload tx must carry CH1"
        );
        assert_eq!(ptx.chain_id(), Some(TEST_CHAIN_ID));
        assert!(ptx.verify_signature(), "a bound payload tx must verify");
        assert!(ptx.verify_signature_for_chain(TEST_CHAIN_ID, true));
        assert!(!ptx.verify_signature_for_chain(OTHER_CHAIN_ID, true));
    }

    /// The legacy hatch builds the old UNBOUND transaction (verifies, but
    /// carries no chain id and fails every strict check) — and it exists so
    /// the warning has exactly one call site to find.
    #[test]
    fn unbound_legacy_hatch_builds_replayable_transactions() {
        let wallet = WalletAccount::from_seed(&[0x51u8; 32]);
        let tx = wallet.unbound_legacy_transfer([0x99u8; 32], 1_000, 5, 0, 0);
        assert!(
            !tx.is_chain_id_bound(),
            "the legacy hatch must stay unbound"
        );
        assert_eq!(tx.chain_id(), None);
        assert!(tx.verify_signature(), "unbound transactions still verify");
        assert!(
            tx.verify_signature_for_chain(TEST_CHAIN_ID, false),
            "legacy transactions pass only the non-strict check"
        );
        assert!(
            !tx.verify_signature_for_chain(TEST_CHAIN_ID, true),
            "strict admission refuses the legacy hatch"
        );

        let ptx =
            wallet.unbound_legacy_payload_transaction(vec![crate::svm::OpCode::Nop], 100_000, 6);
        assert!(!ptx.is_chain_id_bound());
        assert_eq!(ptx.chain_id(), None);
        assert!(ptx.verify_signature());
        assert!(!ptx.verify_signature_for_chain(TEST_CHAIN_ID, true));
    }
}
