/*
 * Copyright (c) 2025 Cambridge State Machines
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define _CRT_RAND_S // prerequisite for the (cryptographically secure) rand_s function, part of the Windows stdlib

#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* MISCELLANEOUS */

const char bip39_wds[2048][9] = {"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"};

uint8_t *init_uint8_array(int32_t);

uint8_t *init_uint8_array(int32_t len)
{
    uint8_t *uint8_array = NULL;
    if (!(uint8_array = malloc(len))) return NULL;
    memset(uint8_array, 0, len);
    return uint8_array;
}

/* RIPEMD160 */

uint32_t rol(uint32_t, uint8_t);
void ripemd160_compute_line(uint32_t *, uint32_t *, uint32_t *, uint8_t *, uint8_t *, uint32_t *, uint8_t *);
void ripemd160_update_digest(uint32_t *, uint32_t *);
void ripemd160(const uint8_t *, uint32_t, uint8_t *);

uint32_t ripemd160_initial_digest[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

uint8_t ripemd160_rho[16] = { 0x7, 0x4, 0xd, 0x1, 0xa, 0x6, 0xf, 0x3, 0xc, 0x0, 0x9, 0x5, 0x2, 0xe, 0xb, 0x8 };

uint8_t ripemd160_shifts[80] = { 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7, 13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9, 14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6, 15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5 };

uint32_t ripemd160_constants_left[5] = { 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e };

uint32_t ripemd160_constants_right[5] = { 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 };

uint8_t ripemd160_fns_left[5]  = { 1, 2, 3, 4, 5 };

uint8_t ripemd160_fns_right[5] = { 5, 4, 3, 2, 1 };

uint32_t rol(uint32_t x, uint8_t n)
{
    return (((x) << (n)) | ((x) >> (32 - (n))));
}

void ripemd160_compute_line(uint32_t* digest, uint32_t* words, uint32_t* chunk, uint8_t* index, uint8_t* shifts, uint32_t* ks, uint8_t* fns)
{
    for (uint8_t i = 0; i < 5; i++) {
        words[i] = digest[i];
    }

    for (uint8_t round = 0; /* breaks out mid-loop */; round++) {
        uint32_t k  = ks[round];
        uint8_t  fn = fns[round];
        for (uint8_t i = 0; i < 16; i++) {
            uint32_t tmp;
            switch (fn) {
                case 1:
                    tmp = words[1] ^ words[2] ^ words[3];
                    break;
                case 2:
                    tmp = (words[1] & words[2]) | (~words[1] & words[3]);
                    break;
                case 3:
                    tmp = (words[1] | ~words[2]) ^ words[3];
                    break;
                case 4:
                    tmp = (words[1] & words[3]) | (words[2] & ~words[3]);
                    break;
                case 5:
                    tmp = words[1] ^ (words[2] | ~words[3]);
                    break;
            }
            tmp += words[0] + chunk[index[i]] + k;
            tmp = rol(tmp, shifts[index[i]]) + words[4];
            words[0] = words[4];
            words[4] = words[3];
            words[3] = rol(words[2], 10);
            words[2] = words[1];
            words[1] = tmp;
        }
        if (round == 4) {
            break;
        }
        shifts += 16;

        uint8_t index_tmp[16];
        for (uint8_t i = 0; i < 16; i++) {
            index_tmp[i] = ripemd160_rho[index[i]];
        }
        for (uint8_t i = 0; i < 16; i++) {
            index[i] = index_tmp[i];
        }
    }
}

void ripemd160_update_digest(uint32_t* digest, uint32_t* chunk)
{
    uint8_t index[16];

    /* initial permutation for left line is the identity */
    for (uint8_t i = 0; i < 16; i++) {
        index[i] = i;
    }
    uint32_t words_left[5];
    ripemd160_compute_line(digest, words_left, chunk, index, ripemd160_shifts, ripemd160_constants_left, ripemd160_fns_left);

    /* initial permutation for right line is 5+9i (mod 16) */
    index[0] = 5;
    for (uint8_t i = 1; i < 16; i++) {
        index[i] = (index[i-1] + 9) & 0x0f;
    }
    uint32_t words_right[5];
    ripemd160_compute_line(digest, words_right, chunk, index, ripemd160_shifts, ripemd160_constants_right, ripemd160_fns_right);

    /* update digest */
    digest[0] += words_left[1] + words_right[2];
    digest[1] += words_left[2] + words_right[3];
    digest[2] += words_left[3] + words_right[4];
    digest[3] += words_left[4] + words_right[0];
    digest[4] += words_left[0] + words_right[1];

    /* final rotation */
    words_left[0] = digest[0];
    digest[0] = digest[1];
    digest[1] = digest[2];
    digest[2] = digest[3];
    digest[3] = digest[4];
    digest[4] = words_left[0];
}

void ripemd160(const uint8_t* data, uint32_t data_len, uint8_t* digest_bytes)
{
    /* NB assumes correct endianness */
    uint32_t *digest = (uint32_t*)digest_bytes;
    for (uint8_t i = 0; i < 5; i++) {
        digest[i] = ripemd160_initial_digest[i];
    }

    const uint8_t *last_chunk_start = data + (data_len & (~0x3f));
    while (data < last_chunk_start) {
        ripemd160_update_digest(digest, (uint32_t*)data);
        data += 0x40;
    }

    uint8_t last_chunk[0x40];
    uint8_t leftover_size = data_len & 0x3f;
    for (uint8_t i = 0; i < leftover_size; i++) {
        last_chunk[i] = *data++;
    }

    /* append a single 1 bit and then zeroes, leaving 8 bytes for the length at the end */
    last_chunk[leftover_size] = 0x80;
    for (uint8_t i = leftover_size + 1; i < 0x40; i++) {
        last_chunk[i] = 0;
    }

    if (leftover_size >= 0x38) {
        /* no room for size in this chunk, add another chunk of zeroes */
        ripemd160_update_digest(digest, (uint32_t*)last_chunk);
        for (uint8_t i = 0; i < 0x38; i++) {
            last_chunk[i] = 0;
        }
    }

    uint32_t *length_lsw = (uint32_t *)(last_chunk + 0x38);
    *length_lsw = (data_len << 3);
    uint32_t *length_msw = (uint32_t *)(last_chunk + 0x3c);
    *length_msw = (data_len >> 29);

    ripemd160_update_digest(digest, (uint32_t*)last_chunk);
}

/* SHA256 */

typedef struct {
    uint32_t state[8];
    uint8_t block[64];
    uint64_t n_bits;
    uint8_t buffer_counter;
} SHA256_CTX;

uint32_t rotr32(uint32_t, int);
uint32_t sha256_f1(uint32_t, uint32_t, uint32_t);
uint32_t sha256_f2(uint32_t, uint32_t, uint32_t);
void update_w(uint32_t *, int, const uint8_t *);
void sha256_block(SHA256_CTX *);
void sha256_init(SHA256_CTX *);
void sha256_append(SHA256_CTX *, const uint8_t *, size_t);
void sha256_finalize(SHA256_CTX *, uint8_t *);
void sha256(const uint8_t *, size_t, uint8_t *);

uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

uint32_t sha256_f1(uint32_t e, uint32_t f, uint32_t g)
{
    return (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) ^ ((~ e) & g));
}

uint32_t sha256_f2(uint32_t a, uint32_t b, uint32_t c)
{
    return (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
}

void update_w(uint32_t *w, int i, const uint8_t *block)
{
    size_t j;
    uint32_t a, b, s0, s1;
    for (j = 0; j < 16; j++) {
        if (i < 16) {
            w[j] = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) | ((uint32_t)block[2] <<  8) | ((uint32_t)block[3]);
            block += 4;
        } else {
            a = w[(j + 1) & 15];
            b = w[(j + 14) & 15];
            s0 = (rotr32(a, 7) ^ rotr32(a, 18) ^ (a >> 3));
            s1 = (rotr32(b, 17) ^ rotr32(b, 19) ^ (b >> 10));
            w[j] += w[(j + 9) & 15] + s0 + s1;
        }
    }
}

void sha256_block(SHA256_CTX *ctx)
{
    int i, j;
    uint32_t a, b, c, d, e, f, g, h, w[16], temp;

    static const uint32_t k[8 * 8] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    w[16];

    for (i = 0; i < 64; i += 16) {
        update_w(w, i, ctx->block);

        for (j = 0; j < 16; j += 4) {
            temp = h + sha256_f1(e, f, g) + k[i + j + 0] + w[j + 0];
            h = temp + d;
            d = temp + sha256_f2(a, b, c);
            temp = g + sha256_f1(h, e, f) + k[i + j + 1] + w[j + 1];
            g = temp + c;
            c = temp + sha256_f2(d, a, b);
            temp = f + sha256_f1(g, h, e) + k[i + j + 2] + w[j + 2];
            f = temp + b;
            b = temp + sha256_f2(c, d, a);
            temp = e + sha256_f1(f, g, h) + k[i + j + 3] + w[j + 3];
            e = temp + a;
            a = temp + sha256_f2(b, c, d);
        }
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->n_bits = 0;
    ctx->buffer_counter = 0;
}

void sha256_append_byte(SHA256_CTX *ctx, uint8_t byte)
{
    ctx->block[ctx->buffer_counter++] = byte;
    ctx->n_bits += 8;

    if (ctx->buffer_counter == 64) {
        ctx->buffer_counter = 0;
        sha256_block(ctx);
    }
}

void sha256_append(SHA256_CTX *ctx, const uint8_t *message, size_t size)
{
    int i;
    for (i = 0; i < size; i++) {
        sha256_append_byte(ctx, message[i]);
    }
}

void sha256_finalize(SHA256_CTX *ctx, uint8_t *digest)
{
    uint8_t byte;
    int i;
    uint64_t n_bits = ctx->n_bits;

    sha256_append_byte(ctx, 0x80);

    while (ctx->buffer_counter != 56) {
        sha256_append_byte(ctx, 0);
    }

    for (i = 7; i >= 0; i--) {
        byte = (n_bits >> 8 * i) & 0xff;
        sha256_append_byte(ctx, byte);
    }

    /* extract uint32_t state[8] into uint8_t digest[32] */
    for (i = 0; i < 8; i++) {
        digest[(i * 4)] = (ctx->state[i] >> 24) & 0xff;
        digest[(i * 4) + 1] = (ctx->state[i] >> 16) & 0xff;
        digest[(i * 4) + 2] = (ctx->state[i] >> 8) & 0xff;
        digest[(i * 4) + 3] = (ctx->state[i]) & 0xff;
    }
}

void sha256(const uint8_t *message, size_t size, uint8_t *digest)
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_append(&ctx, message, size);
    sha256_finalize(&ctx, digest);
}

/* SHA512 */

typedef struct {
    uint64_t state[8];
    uint8_t block[256];
    uint32_t tot_len;
    size_t len;
} SHA512_CTX;

uint64_t rotr64(uint64_t, int);
uint64_t rotl64(uint64_t, int);
uint64_t shfr64(uint64_t, int);
uint64_t ch(uint64_t, uint64_t, uint64_t);
uint64_t maj(uint64_t, uint64_t, uint64_t);
uint64_t sha512_f1(uint64_t);
uint64_t sha512_f2(uint64_t);
uint64_t sha512_f3(uint64_t);
uint64_t sha512_f4(uint64_t);
void sha512_transf(SHA512_CTX *, const uint8_t *, uint32_t);
void sha512_init(SHA512_CTX *);
void sha512_update(SHA512_CTX *, const uint8_t *, size_t);
void sha512_finalize(SHA512_CTX *, uint8_t *);
void sha512(const uint8_t *, size_t, uint8_t *);

uint64_t sha512_k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};
             
uint64_t sha512_h0[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

uint64_t rotr64(uint64_t x, int n)
{
    return (x >> n) | (x << (64 - n));
}

uint64_t rotl64(uint64_t x, int n)
{
    return (x << n) | (x >> (64 - n));
}

uint64_t shfr64(uint64_t x, int n)
{
    return x >> n;
}

uint64_t ch(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (~x & z);
}

uint64_t maj(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

uint64_t sha512_f1(uint64_t x)
{
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

uint64_t sha512_f2(uint64_t x)
{
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

uint64_t sha512_f3(uint64_t x)
{
    return rotr64(x, 1) ^ rotr64(x, 8) ^ shfr64(x, 7);
}

uint64_t sha512_f4(uint64_t x)
{
    return rotr64(x, 19) ^ rotr64(x, 61) ^ shfr64(x, 6);
}

void sha512_transf(SHA512_CTX *ctx, const uint8_t *message, uint32_t block_nb)
{
    int i, j, pos;
    uint64_t w[80], wv[8], t1, t2;

    for (i = 0; i < block_nb; i++) {

        for (j = 0; j < 16; j++) {
            pos = (i * 128) + (j * 8);
            w[j] = ((uint64_t)(message[pos]) << 56) + ((uint64_t)(message[pos + 1]) << 48) + ((uint64_t)(message[pos + 2]) << 40) + ((uint64_t)(message[pos + 3]) << 32) + ((uint64_t)(message[pos + 4]) << 24) + ((uint64_t)(message[pos + 5]) << 16) + ((uint64_t)(message[pos + 6]) << 8) + (uint64_t)(message[pos + 7]);
        }

        for (j = 16; j < 80; j++) {
            w[j] = sha512_f4(w[j -  2]) + w[j -  7] + sha512_f3(w[j - 15]) + w[j - 16];
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->state[j];
        }

        for (j = 0; j < 80; j++) {
            t1 = wv[7] + sha512_f2(wv[4]) + ch(wv[4], wv[5], wv[6]) + sha512_k[j] + w[j];
            t2 = sha512_f1(wv[0]) + maj(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->state[j] += wv[j];
        }
    }
}

void sha512_init(SHA512_CTX *ctx)
{
    int i;
    for (i = 0; i < 8; i++) {
        ctx->state[i] = sha512_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha512_update(SHA512_CTX *ctx, const uint8_t *message, size_t len)
{
    uint32_t block_nb, new_len, rem_len, tmp_len;
    const uint8_t *shifted_message;

    tmp_len = 128 - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < 128) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / 128;

    shifted_message = message + rem_len;

    sha512_transf(ctx, ctx->block, 1);
    sha512_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % 128;

    memcpy(ctx->block, &shifted_message[block_nb << 7], rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 7;
}

void sha512_finalize(SHA512_CTX *ctx, uint8_t *digest)
{
    uint32_t block_nb, pm_len, len_b;

    int i;

    block_nb = 1 + (111 < (ctx->len % 128));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 7;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    ctx->block[pm_len - 1] = (uint8_t)((len_b));
    ctx->block[pm_len - 2] = (uint8_t)((len_b) >>  8);
    ctx->block[pm_len - 3] = (uint8_t)((len_b) >> 16);
    ctx->block[pm_len - 4] = (uint8_t)((len_b) >> 24);

    sha512_transf(ctx, ctx->block, block_nb);

    for (i = 0 ; i < 8; i++) {
        digest[(i * 8) + 7] = (uint8_t)(ctx->state[i]);
        digest[(i * 8) + 6] = (uint8_t)((ctx->state[i]) >> 8);
        digest[(i * 8) + 5] = (uint8_t)((ctx->state[i]) >> 16);
        digest[(i * 8) + 4] = (uint8_t)((ctx->state[i]) >> 24);
        digest[(i * 8) + 3] = (uint8_t)((ctx->state[i]) >> 32);
        digest[(i * 8) + 2] = (uint8_t)((ctx->state[i]) >> 40);
        digest[(i * 8) + 1] = (uint8_t)((ctx->state[i]) >> 48);
        digest[(i * 8) + 0] = (uint8_t)((ctx->state[i]) >> 56);
    }
}

void sha512(const uint8_t *message, size_t len, uint8_t *digest)
{
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, message, len);
    sha512_finalize(&ctx, digest);
}

/* HMAC-SHA512 */

typedef struct {
    SHA512_CTX ctx_inside;
    SHA512_CTX ctx_outside;
    SHA512_CTX ctx_inside_reinit;
    SHA512_CTX ctx_outside_reinit;
    uint8_t block_ipad[128];
    uint8_t block_opad[128];
} HMAC_SHA512_CTX;

void hmac_sha512_init(HMAC_SHA512_CTX *, const uint8_t *, uint32_t);
void hmac_sha512_reinit(HMAC_SHA512_CTX *);
void hmac_sha512_update(HMAC_SHA512_CTX *, const uint8_t *, uint32_t);
void hmac_sha512_final(HMAC_SHA512_CTX *, uint8_t *, uint32_t);
void hmac_sha512(const uint8_t *, uint32_t, const uint8_t *, uint32_t, uint8_t *, uint32_t);

void hmac_sha512_init(HMAC_SHA512_CTX *ctx, const uint8_t *key, uint32_t key_size)
{
    uint8_t key_temp[64];
    const uint8_t *key_used;
    uint32_t fill, num;
    int i;
    if (key_size == 128) {
        key_used = key;
        num = 128;
    } else {
        if (key_size > 128){
            num = 64;
            sha512(key, key_size, key_temp);
            key_used = key_temp;
        } else { /* key_size > 128 */
            key_used = key;
            num = key_size;
        }
        fill = 128 - num;
        memset(ctx->block_ipad + num, 0x36, fill);
        memset(ctx->block_opad + num, 0x5c, fill);
    }

    for (i = 0; i < (int) num; i++) {
        ctx->block_ipad[i] = key_used[i] ^ 0x36;
        ctx->block_opad[i] = key_used[i] ^ 0x5c;
    }

    sha512_init(&ctx->ctx_inside);
    sha512_update(&ctx->ctx_inside, ctx->block_ipad, 128);

    sha512_init(&ctx->ctx_outside);
    sha512_update(&ctx->ctx_outside, ctx->block_opad, 128);

    /* for hmac_reinit */
    memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside, sizeof(SHA512_CTX));
    memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside, sizeof(SHA512_CTX));
}

void hmac_sha512_reinit(HMAC_SHA512_CTX *ctx)
{
    memcpy(&ctx->ctx_inside, &ctx->ctx_inside_reinit, sizeof(SHA512_CTX));
    memcpy(&ctx->ctx_outside, &ctx->ctx_outside_reinit, sizeof(SHA512_CTX));
}

void hmac_sha512_update(HMAC_SHA512_CTX *ctx, const uint8_t *message, uint32_t message_len)
{
    sha512_update(&ctx->ctx_inside, message, message_len);
}

void hmac_sha512_final(HMAC_SHA512_CTX *ctx, uint8_t *mac, uint32_t mac_size)
{
    uint8_t digest_inside[64], mac_temp[64];
    sha512_finalize(&ctx->ctx_inside, digest_inside);
    sha512_update(&ctx->ctx_outside, digest_inside, 64);
    sha512_finalize(&ctx->ctx_outside, mac_temp);
    memcpy(mac, mac_temp, mac_size);
}

void hmac_sha512(const uint8_t *key, uint32_t key_size, const uint8_t *message, uint32_t message_len, uint8_t *mac, uint32_t mac_size)
{
    HMAC_SHA512_CTX ctx;
    hmac_sha512_init(&ctx, key, key_size);
    hmac_sha512_update(&ctx, message, message_len);
    hmac_sha512_final(&ctx, mac, mac_size);
}

/* BNZ */

typedef struct {
    size_t sign;
    size_t size;
    uint8_t *digits;
} bnz_t;

void bnz_init(bnz_t *);
void bnz_resize(bnz_t *, size_t, int32_t);
void bnz_align(bnz_t *, bnz_t *);
void bnz_reverse_digits(bnz_t *); 
void bnz_shift_r(bnz_t *, uint32_t);
void bnz_trim(bnz_t *);
void bnz_print(const bnz_t *, int32_t, const char *);
void bnz_free(bnz_t *);

int8_t get_digit(const uint8_t *, size_t, uint8_t);
uint8_t *get_base_n_str(const bnz_t *, uint32_t, const char *, uint32_t *);

void bnz_set_i32(bnz_t *, int32_t);
void bnz_set_ui32(bnz_t *, uint32_t);
void bnz_set_str(bnz_t *, const uint8_t *, uint8_t);
void bnz_set_bnz(bnz_t *, const bnz_t *);

int32_t cmp_uint8_arr(uint8_t *, uint8_t *, size_t);
int32_t bnz_cmp_i32(const bnz_t *, int32_t);
int32_t bnz_cmp_bnz(const bnz_t *, const bnz_t *);
int32_t bnz_is_zero(const bnz_t *);
int32_t bnz_bit_set(const bnz_t *, uint32_t);

void bnz_concatenate_ui8(bnz_t *, const bnz_t *, uint8_t, size_t);
void bnz_concatenate_bnz(bnz_t *, const bnz_t *, const bnz_t *, size_t);

void bnz_add_i32(bnz_t *, const bnz_t *, int32_t);
void bnz_add_bnz(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_addition(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_subtract_bnz(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_subtraction(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_multiply_i32(bnz_t *, const bnz_t *, int32_t);
void bnz_multiply_bnz(bnz_t *, const bnz_t *, const bnz_t *);
void bnz_division_signs(bnz_t *, bnz_t *, const bnz_t *, const bnz_t *);
void bnz_divide_bnz(bnz_t *, bnz_t *, const bnz_t *, const bnz_t *);
void bnz_division(bnz_t *, bnz_t *, const bnz_t *, const bnz_t *);
void bnz_mod_bnz(bnz_t *, const bnz_t *, const bnz_t *);

void bnz_mod_pow(bnz_t *, const bnz_t *, const bnz_t *, const bnz_t *);
void bnz_modular_multiplicative_inverse(bnz_t *, const bnz_t *, const bnz_t *);

int8_t char_16[256] = { // ascii - hex
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  10,  11,  12,  13,  14,  15,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  10,  11,  12,  13,  14,  15,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

int8_t char_32[256] = { // ascii - Bech32
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    15,  -1,  10,  17,  21,  20,  26,  30,   7,   5,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  29,  -1,  24,  13,  25,   9,   8,  23,  -1,  18,  22,  31,  27,  19,  -1,
     1,   0,   3,  16,  11,  28,  12,  14,   6,   4,   2,  -1,  -1,  -1,  -1,  -1,
    -1,  29,  -1,  24,  13,  25,   9,   8,  23,  -1,  18,  22,  31,  27,  19,  -1,
     1,   0,   3,  16,  11,  28,  12,  14,   6,   4,   2,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

int8_t char_58[256] = { // ascii - Bitcoin base 58
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,   0,   1,   2,   3,   4,   5,   6,   7,   8,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,   9,  10,  11,  12,  13,  14,  15,  16,  -1,  17,  18,  19,  20,  21,  -1,
    22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  -1,  -1,  -1,  -1,  -1,
    -1,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  -1,  44,  45,  46,
    47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

int8_t char_64[256] = { // ascii - base 64
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  62,  -1,  -1,  -1,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
    15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  -1,  -1,  -1,  -1,  -1,
    -1,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
    41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

int8_t char_d[256] = {  // ascii - general
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
    25,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  -1,  -1,  -1,  -1,  62,
    -1,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,
    51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1
};

void bnz_init(bnz_t *a) // initiate bnz_t components
{
    a->sign = 0;
    a->size = 0;
    a->digits = NULL;
}

void bnz_resize(bnz_t *a, size_t new_size, int32_t preserve) // increase or decrease number of bytes in a->digits, zeroing added bytes, and preserving or zeroing existing bytes
{
    uint8_t *tmp = NULL;
    size_t prev_size = a->size;
    if (new_size < 1) new_size = 1;
    tmp = realloc(a->digits, new_size);
    if (tmp) {
        if (preserve) {
            if (new_size > prev_size) memset(tmp + prev_size, 0, new_size - prev_size); // zero new bytes
        } else {
            a->sign = 0;
            memset(tmp, 0, new_size); //zero all bytes
        }
        a->digits = tmp;
        a->size = new_size;
    }
}

void bnz_align(bnz_t *a, bnz_t *b) // resize a->digits or b->digits to match the byte count of the longer of a and b
{
    bnz_trim(a);
    bnz_trim(b);
    if (a->size > b->size) {
        bnz_resize(b, a->size, 1);
    } else {
        bnz_resize(a, b->size, 1);
    }
}

void bnz_reverse_digits(bnz_t *a) // reverse the order of the bytes in a->digits
{
    uint8_t tmp;
    size_t i = 0, j = a->size - 1;
    while (i < j) {
        tmp = a->digits[i];
        a->digits[i] = a->digits[j];
        a->digits[j] = tmp;
        i++;
        j--;
    }
}

void bnz_shift_r(bnz_t *a, uint32_t sh) // shift the bits in a->digits to the right by sh bits, adding 0 value bits to msb end
{
    uint8_t msk = 255 >> (8 - sh);
    size_t i, orig_size = a->size;
    if (sh < 1 || sh > 7) return;
    bnz_resize(a, orig_size + 1, 1);
    bnz_reverse_digits(a);
    for (i = a->size - 1; i > 0; i--) {
        a->digits[i] = (a->digits[i - 1] & msk) << (8 - sh) | a->digits[i] >> sh;
    }
    bnz_reverse_digits(a);
    bnz_resize(a, orig_size, 1);
}

void bnz_trim(bnz_t *a) // trim 0 value bytes from msb end of a->digits
{
    size_t new_size = a->size;
    while (a->digits[new_size - 1] == 0 && new_size >= 0) {
        new_size--;
    }
    bnz_resize(a, new_size, 1);
}

void bnz_print(const bnz_t *a, int32_t base, const char *txt) // print a in a given base, preceded by optional string 
{
    uint8_t *str = NULL;
    uint32_t i, j, len;
    bnz_t tmp;

    bnz_init(&tmp);

    bnz_set_bnz(&tmp, a);

    bnz_reverse_digits(&tmp);

    switch (base) {
        case -2: // binary with spaces between bytes
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("0\n");
            } else {
                if (tmp.sign) printf("-");
                for (i = 0; i < tmp.size; i++) { // traverse bytes
                    for (j = 0; j < 8; j++) { // divide each byte into 8 bits
                        printf("%d", (tmp.digits[i] >> (7 - j)) & 1);
                    }
                    printf(" "); // add space between each byte
                }
                printf("\n");
            }
            break;
        case 2: // binary
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("0\n");
            } else {
                if (tmp.sign) printf("-");
                for (i = 0; i < tmp.size; i++) { // traverse bytes
                    for (j = 0; j < 8; j++) { // divide each byte into 8 bits
                        printf("%d", (tmp.digits[i] >> (7 - j)) & 1);
                    }
                }
                printf("\n");
            }
            break;
        case -16: // hex, upper case, without "0x" prefix, same as default for 0 to F
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("0\n");
            } else {
                if (!(str = get_base_n_str(&tmp, 16, "0123456789ABCDEF", &len))) return;
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 16: // hex, lower case with "0x" prefix
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("0x0\n");
            } else {
                if (tmp.sign) printf("-");
                printf("0x");
                for (i = 0; i < tmp.size; i++) {
                    printf("%02x", tmp.digits[i]);
                }
                printf("\n");
            }
            break;
        case -32: // standard base 32
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("0\n");
            } else {
                if (!(str = get_base_n_str(&tmp, 32, "0123456789ABCDEFGHIJKLMNOPQRSTUV", &len))) return;
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 32: // bech32
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("q\n");
            } else {
                if (!(str = get_base_n_str(&tmp, 32, "qpzry9x8gf2tvdw0s3jn54khce6mua7l", &len))) return;
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case -58: // standard base 58
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("0\n");
            } else {
                if (!(str = get_base_n_str(&tmp, 58, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv", &len))) return;
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 58: // bitcoin base 58
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("1\n");
            } else {
                if (!(str = get_base_n_str(&tmp, 58, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", &len))) return;
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 64:
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("A\n");
            } else {
                if (!(str = get_base_n_str(&tmp, 64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", &len))) return;
                if (tmp.sign) printf("-");
                printf("%s\n", str);
            }
            break;
        case 256: // individual byte values, base 10, separated by ", "
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("0\n");
            } else {
                if (tmp.sign) printf("-");
                printf("%d", tmp.digits[0]);
                for (i = 1; i < tmp.size; i++) {
                    printf(", %d", tmp.digits[i]);
                }
                printf("\n");
            }
            break;
        default: // default for 2 to 63
            printf("%s", txt);
            if (bnz_is_zero(&tmp)) {
                printf("0\n");
            } else {
                if (base >= 2 && base <= 63) {
                    if (!(str = get_base_n_str(&tmp, base, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_", &len))) return;
                    if (tmp.sign) printf("-");
                    printf("%s\n", str);
                }
            }
            break;
    }

    bnz_free(&tmp);
    free(str);
}

void bnz_free(bnz_t *a) // free bnz_t resources
{
    a->sign = 0;
    a->size = 0;
    free(a->digits);
    a->digits = NULL;
}

int8_t get_digit(const uint8_t *str, size_t idx, uint8_t base) // return numerical value of char at index idx of str representing a number in the given base and in big endian order
{
    int8_t dgt;
    switch (base) {
        case 16:
            dgt = char_16[str[idx]];
            break;
        case 32:
            dgt = char_32[str[idx]];
            break;
        case 58:
            dgt = char_58[str[idx]];
            break;
        case 64:
            dgt = char_64[str[idx]];
            break;
        default:
            if (base >= 2 && base <= 63) dgt = char_d[str[idx]];
            break;
    }
    if (dgt < 0 || dgt >= base) return -1;
    return dgt;
}

uint8_t *get_base_n_str(const bnz_t *a, uint32_t base, const char *alpha, uint32_t *len) // return a null terminated string representing a->digits in given base, big endian order
{
    uint8_t *base_n_str = NULL, *base_n_str_trimmed = NULL;
    size_t i, j, k, trim = 0;

    (*len) = (a->size * log10((double)256)) / log10((double)abs(base)) + 1;

    if (!(base_n_str = init_uint8_array((*len) + 1))) return NULL;

    for (i = 0; i < a->size; i++) {
        k = a->digits[i];
        for (j = (*len); j > 0; j--) {
            k += (uint32_t)base_n_str[j - 1] * 256;
            base_n_str[j - 1] = (uint8_t)(k % abs(base));
            k /= abs(base);
        }
    }

    while ((base == 32 && alpha[base_n_str[trim]] == 'q') || (base == 58 && alpha[base_n_str[trim]] == '1') || (base == 64 && alpha[base_n_str[trim]] == 'A') || (base != 64 && alpha[base_n_str[trim]] == '0')) { // trim leading zeros at msb end, 'q' for Bech32, '1' for Bitcoin base 58, 'A' for base 64
        trim++;
        (*len)--;
    }

    if (!(base_n_str_trimmed = init_uint8_array((*len) + 1))) return NULL;

    for (i = 0; i < (*len); i++) {
        base_n_str_trimmed[i] = alpha[base_n_str[i + trim]];
    }

    free(base_n_str);
    return base_n_str_trimmed;
}

void bnz_set_i32(bnz_t *res, int32_t val) // set bnz_t to 32 bit signed int
{
    if (val < 0) { // val is negative
        res->sign = 1; // sign == 1 for negative val, 0 for positive val
        val *= -1; // multiply negative int32_t by -1 to de-complement bytes
    }
    bnz_resize(res, 4, 0); // resize res to 4 bytes, zero bytes
    memcpy(res->digits, &val, 4); // copy bytes from val to res->digits
    bnz_trim(res); // trim zero bytes from msb end
}

void bnz_set_ui32(bnz_t *res, uint32_t val) // set bnz_t to 32 bit unsigned int
{
    bnz_resize(res, 4, 0); // resize res to 4 bytes, zero bytes
    memcpy(res->digits, &val, 4); // copy bytes from val to res->digits
    bnz_trim(res); // trim zero bytes from msb end
}

void bnz_set_str(bnz_t *res, const uint8_t *str, uint8_t base) // set bnz_t to number represented by str with radix between 2 and 64, and with its digits in big endian order
{
    int32_t dgt;
    size_t i, j, len = (size_t)((double)strlen(str) * log(base)/log(256)) + 1, idx = 0;
    bnz_resize(res, len, 0);
    if (str[0] == '-') { // if first symbol of str is "-", set sign to 1 and set starting index of digits to 1 
        res->sign = 1;
        idx = 1;
    }
    for (i = idx; i < strlen(str); i++) {
        dgt = get_digit(str, i, base);
        if (dgt != -1) {
            for (j = len; j > 0; j--) {
                dgt += res->digits[j - 1] * base;
                res->digits[j - 1] = dgt & 255;
                dgt >>= 8;
            }
        }
    }
    bnz_reverse_digits(res); // convert a->digits to little endian order
    bnz_trim(res); // trim zero bytes from msb end
}

void bnz_set_bnz(bnz_t *res, const bnz_t *val) // set bnz_t equivalent to another bnz_t
{
    bnz_resize(res, val->size, 0);
    memcpy(res->digits, val->digits, val->size);
    res->sign = val->sign;
}

int32_t cmp_uint8_arr(uint8_t *a, uint8_t *b, size_t len) // compare two 1D uint8_t arrays a and b, from msb to lsb, return -1 if a < b, 0 if a == b, and 1 if a > b 
{
    size_t idx = len;
    while (idx--) {
        if (a[idx] > b[idx]) return 1;
        if (a[idx] < b[idx]) return -1;
    }
    return 0;
}

int32_t bnz_cmp_i32(const bnz_t *a, int32_t b) // compare bnz_t with int32_t by converting int32_t to bnz_t and invoking bnz_cmp_bnz
{
    int32_t res;
    bnz_t tmp;
    bnz_init(&tmp);
    bnz_set_i32(&tmp, b);
    res = bnz_cmp_bnz(a, &tmp);
    bnz_free(&tmp);
    return res;
}

int32_t bnz_cmp_bnz(const bnz_t *a, const bnz_t *b) // compare two bnz_t numbers, taking account of signs, and invoking cmp_uint8_arr to compare their digits
{
    size_t res;
    bnz_t aa, bb;

    bnz_init(&aa);
    bnz_init(&bb);
    
    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);
    bnz_align(&aa, &bb);
    
    if (aa.sign != bb.sign) { // signs are different
        if (aa.sign == 0 && bb.sign != 0) {
            res = 1; // a > -b
        } else {
            res = -1; // -a < b
        }
    } else { // signs are the same
        res = cmp_uint8_arr(aa.digits, bb.digits, aa.size); // compare |a| and |b|
        switch (res) {
            case -1: // |a| < |b| => a < b, -a > -b
                if (aa.sign) res = 1; // reverse cmp value if a and b are negative
                break;
            case 1: // |a| > |b| => a > b, -a < -b
                if (aa.sign) res = -1; // reverse cmp value if a and b are negative
                break;
            default:
                break;
        }
    }

    bnz_free(&aa);
    bnz_free(&bb);

    return res;
}

int32_t bnz_is_zero(const bnz_t *val) // return 1 if val == 0, return 0 if val != 0
{
    size_t i = val->size;
    while (i--) {
        if (val->digits[i] != 0) return 0;
    }
    return 1;
}

int32_t bnz_bit_set(const bnz_t *val, uint32_t idx) // return 1 if the specified bit in val is set, return 0 if it is not set
{
    uint32_t byte = idx / 8, bit = idx % 8;
    return (val->digits[byte] >> bit) & 1;
}

void bnz_concatenate_ui8(bnz_t *res, const bnz_t *a, uint8_t b, size_t order) // convert uint8_t to bnz_t and invoke bnz_concatenate_bnz
{
    bnz_t bb;
    bnz_init(&bb);
    bnz_resize(&bb, 1, 0);
    memcpy(bb.digits, &b, 1);
    bnz_concatenate_bnz(res, a, &bb, order);
    bnz_free(&bb);
}

void bnz_concatenate_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b, size_t order) // res = a || b, in specified order
{
    bnz_t tmp; // local variable permits a = a || b, a = b || a
    bnz_init(&tmp);
    bnz_resize(&tmp, a->size + b->size, 0);
    if (order) {
        memcpy(tmp.digits, b->digits, b->size);
        memcpy(tmp.digits + b->size, a->digits, a->size);
    } else {
        memcpy(tmp.digits, a->digits, a->size);
        memcpy(tmp.digits + a->size, b->digits, b->size);
    }
    bnz_set_bnz(res, &tmp);
    bnz_free(&tmp);
}

void bnz_add_i32(bnz_t *res, const bnz_t *a, int32_t b) // convert int32_t to bnz_t and invoke bnz_add_bnz
{
    bnz_t bb;
    bnz_init(&bb);
    bnz_set_i32(&bb, b); // convert b to bnz_t
    bnz_add_bnz(res, a, &bb);
    bnz_free(&bb);
}

void bnz_add_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = a + b, taking account of signs, invoking bnz_addition or bnz_subtraction
{
    int32_t cmp;
    bnz_t tmp, aa, bb;

    bnz_init(&tmp);
    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);

    bnz_align(&aa, &bb);

    cmp = cmp_uint8_arr(aa.digits, bb.digits, aa.size);

    if (a->sign) { // -a
        if (b->sign) { // -a, -b
            bnz_addition(&tmp, &aa, &bb);
            tmp.sign = 1;
        } else { // -a, +b
            if (cmp == -1) { // |a| < |b|
                bnz_subtraction(&tmp, &bb, &aa);
                tmp.sign = 0;
            } else { // |a| >= |b|
                bnz_subtraction(&tmp, &aa, &bb);
                tmp.sign = 1;
            }
        }
    } else { // +a
        if (b->sign) { // +a, -b
            if (cmp == -1) { // |a| < |b|
                bnz_subtraction(&tmp, &bb, &aa);
                tmp.sign = 1;
            } else { // |a| >= |b|
                bnz_subtraction(&tmp, &aa, &bb);
                tmp.sign = 0;
            }
        } else { // +a, +b
            bnz_addition(&tmp, &aa, &bb);
        }
    }

    bnz_trim(&tmp);

    bnz_set_bnz(res, &tmp);

    bnz_free(&tmp);
    bnz_free(&aa);
    bnz_free(&bb);
}

void bnz_addition(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = |a| + |b|
{
    size_t i, carry = 0;
    bnz_t tmp;
    bnz_init(&tmp);
    bnz_resize(&tmp, a->size + 1, 0);
    for (i = 0; i < a->size; i++) {
        tmp.digits[i] = a->digits[i] + carry;
        carry = tmp.digits[i] < carry ? 1 : 0;
        tmp.digits[i] += b->digits[i];
        if (tmp.digits[i] < b->digits[i]) carry = 1;
    }
    tmp.digits[a->size] = carry;
    bnz_set_bnz(res, &tmp);
    bnz_free(&tmp);
}

void bnz_subtract_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = a - b, taking account of signs, invoking bnz_subtraction or bnz_addition
{
    int32_t cmp;
    bnz_t tmp, aa, bb;

    bnz_init(&tmp);
    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);

    bnz_align(&aa, &bb);

    cmp = cmp_uint8_arr(aa.digits, bb.digits, aa.size);

    if (a->sign) { // -a
        if (b->sign) { // -a, -b
            if (cmp == -1) { // |a| < |b|
                bnz_subtraction(&tmp, &bb, &aa);
                tmp.sign = 0;
            } else { // |a| >= |b|
                bnz_subtraction(&tmp, &aa, &bb);
                tmp.sign = 1;
            }
        } else { // -a, +b
            bnz_addition(&tmp, &aa, &bb);
            tmp.sign = 1;
        }
    } else { // +a
        if (b->sign) { // +a, -b
            bnz_addition(&tmp, &aa, &bb);
            tmp.sign = 0;
        } else { // +a, +b
            if (cmp == -1) { // |a| < |b|
                bnz_subtraction(&tmp, &bb, &aa);
                tmp.sign = 1;
            } else { // |a| >= |b|
                bnz_subtraction(&tmp, &aa, &bb);
                tmp.sign = 0;
            }
        }
    }

    bnz_trim(&tmp);

    bnz_set_bnz(res, &tmp);

    bnz_free(&tmp);
    bnz_free(&aa);
    bnz_free(&bb);
}

void bnz_subtraction(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = |a| - |b|
{
    size_t i, borrow = 0;
    bnz_t tmp;
    bnz_init(&tmp);
    bnz_resize(&tmp, a->size, 0);
    for (i = 0; i < a->size; i++) {
        tmp.digits[i] = a->digits[i] - borrow;
        borrow = tmp.digits[i] > 255 - borrow ? 1 : 0;
        tmp.digits[i] -= b->digits[i];
        if (tmp.digits[i] > 255 - b->digits[i]) borrow = 1;
    }
    bnz_set_bnz(res, &tmp);
    bnz_free(&tmp);
}

void bnz_multiply_i32(bnz_t *res, const const bnz_t *a, int32_t b) // convert int32_t to bnz_t and invoke bnz_multiply_bnz
{
    bnz_t bb;
    bnz_init(&bb);
    bnz_set_i32(&bb, b);
    bnz_multiply_bnz(res, a, &bb);
    bnz_free(&bb);
}

void bnz_multiply_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = |a| * |b|
{
    uint8_t k, t[2];
    uint16_t m;
    size_t i, j;
    bnz_t tmp, aa, bb;

    bnz_init(&tmp);
    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);

    bnz_align(&aa, &bb);
    bnz_resize(&tmp, aa.size * 2, 0);

    if (a->sign) { // -a
        if (b->sign) { // -a, -b
            tmp.sign = 0;
        } else { // -a, +b
            tmp.sign = 1;
        }
    } else { // +a
        if (b->sign) { // +a, -b
            tmp.sign = 1;
        } else { // +a, +b
            tmp.sign = 0;
        }
    }

    for (i = 0; i < aa.size; i++) {
        if (bb.digits[i] == 0) {
            tmp.digits[i + aa.size] = 0;
        } else {
            k = 0;
            for (j = 0; j < aa.size; j++) {
                m = aa.digits[j] * bb.digits[i];
                t[0] = (m & 255) + k;
                t[1] = (m >> 8) & 255;
                if (t[0] < k) t[1]++;
                t[0] += tmp.digits[j + i];
                if (t[0] < tmp.digits[j + i]) t[1]++;
                tmp.digits[j + i] = t[0];
                k = t[1];
            }    
            tmp.digits[i + aa.size] = k;
        }
    }

    bnz_trim(&tmp);

    bnz_set_bnz(res, &tmp);

    bnz_free(&tmp);
    bnz_free(&aa);
    bnz_free(&bb);
}

void bnz_division_signs(bnz_t *q, bnz_t *r, const bnz_t *a, const bnz_t *b) // process signs of q and r in a / b
{
    if (a->sign) { // -a
        if (b->sign) { // -a, -b
            q->sign = 0; // +q
            r->sign = 1; // -r
        } else { // -a, +b
            q->sign = 1; // -q
            r->sign = 1; // -r
        }
    } else { // +a
        if (b->sign) { // +a, -b
            q->sign = 1; // -q
            r->sign = 0; // +r
        } else { // +a, +b
            q->sign = 0; // +q
            r->sign = 0; // +r
        }
    }
}

void bnz_divide_bnz(bnz_t *q, bnz_t *r, const bnz_t *a, const bnz_t *b) // get q and r of a / b, taking account of signs, invoking bnz_division
{
    int32_t cmp;

    bnz_t aa, bb;

    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);
    bnz_trim(&aa);
    bnz_trim(&bb);

    aa.sign = 0;
    bb.sign = 0;

    if (bnz_is_zero(&bb)) { // divide by 0
        printf("div 0 error\n");
        bnz_set_i32(q, 0);
        bnz_set_i32(r, 0);
        return;
    }

    cmp = bnz_cmp_bnz(&aa, &bb);

    if (cmp == 0) { // |aa| = |bb|
        bnz_set_i32(q, 1);
        bnz_set_i32(r, 0);
        bnz_division_signs(q, r, a, b);
        bnz_free(&aa);
        bnz_free(&bb);
        return;
    }

    if (cmp == -1) { // |aa| < |bb|
        bnz_set_i32(q, 0);
        bnz_set_bnz(r, &aa);
        bnz_division_signs(q, r, a, b);
        bnz_free(&aa);
        bnz_free(&bb);
        return;
    }

    bnz_division(q, r, &aa, &bb); // |aa| > |bb|
    bnz_division_signs(q, r, a, b);

    bnz_free(&aa);
    bnz_free(&bb);   
}

void bnz_division(bnz_t *q, bnz_t *r, const bnz_t *a, const bnz_t *b) // get q and r of |a| / |b|
{
    uint8_t *an = NULL, *bn = NULL, tmp = b->digits[b->size - 1];
    uint16_t q_hat, r_hat, p, base = 256;
    int32_t sh = 0, i, j, t, k, cmp;

    bnz_resize(q, a->size - b->size + 1, 0);
    bnz_resize(r, b->size, 0);

    while (tmp < 128) { // measure left shift required to ensure that the highest bit of bn->digits[bn->size - 1] is set
        sh++;
        tmp <<= 1;
    }

    // an
    if (!(an = init_uint8_array(2 * (a->size + 1)))) return;
    an[a->size] = a->digits[a->size - 1] >> 8 - sh;
    for (i = a->size - 1; i > 0; i--) {
        an[i] = (a->digits[i] << sh) | (a->digits[i-1] >> 8 - sh);
    }
    an[0] = a->digits[0] << sh;

    // bn
    if (!(bn = init_uint8_array(2 * b->size))) return;
    for (i = b->size - 1; i > 0; i--) {
        bn[i] = (b->digits[i] << sh) | (b->digits[i - 1] >> 8 - sh);
    }
    bn[0] = b->digits[0] << sh;

    // main loop
    for (j = a->size - b->size; j >= 0; j--) {
        q_hat = ((an[j + b->size] * base) + an[j + b->size - 1]) / bn[b->size - 1];
        r_hat = ((an[j + b->size] * base) + an[j + b->size - 1]) - (q_hat * bn[b->size - 1]);

        // q_hat adjustment, maximum 2 iterations
        if (q_hat >= base || q_hat * bn[b->size - 2] > (base * r_hat) + an[j + b->size - 2]) { // first iteration
            q_hat -= 1;
            r_hat += bn[b->size - 1];
            if (r_hat < base) { // second iteration
                if (q_hat >= base || q_hat * bn[b->size - 2] > (base * r_hat) + an[j + b->size - 2]) {
                    q_hat -= 1;
                    r_hat += bn[b->size - 1];
                }
            }
        }

        k = 0;
        for (i = 0; i < b->size; i++) {
            p = q_hat * bn[i];
            t = an[i + j] - k - (p & 255);
            an[i + j] = t;
            k = (p >> 8) - (t >> 8);
        }
        t = an[j + b->size] - k;
        an[j + b->size] = t;

        q->digits[j] = q_hat;

        if (t < 0) {
            k = 0;
            q->digits[j] = q->digits[j] - 1;
            for (i = 0; i < b->size; i++) {
                t = an[i + j] + bn[i] + k;
                an[i + j] = t;
                k = t >> 8;
            }
            an[j + b->size] = an[j + b->size] + k;
        }
    }

    for (i = 0; i < b->size; i++) {
        r->digits[i] = (an[i] >> sh) | (an[i + 1] << 8 - sh);
    }

    bnz_trim(q);
    bnz_trim(r);

    free(an);
    free(bn);
}

void bnz_mod_bnz(bnz_t *res, const bnz_t *a, const bnz_t *b) // res = a % b, invoking bnz_divide_bnz
{
    bnz_t q, r;

    bnz_init(&q);
    bnz_init(&r);
    
    bnz_divide_bnz(&q, &r, a, b);
    bnz_trim(&r);
    if (r.sign) bnz_add_bnz(&r, &r, b);
    bnz_set_bnz(res, &r);
    
    bnz_free(&q);
    bnz_free(&r);
}

void bnz_mod_pow(bnz_t *res, const bnz_t *a, const bnz_t *b, const bnz_t *c) // get res = a^b mod c, code adapted from the pseudocode at https://en.wikipedia.org/wiki/Modular_exponentiation
{
    bnz_t aa, bb;

    bnz_init(&aa);
    bnz_init(&bb);

    bnz_set_i32(res, 1);
    bnz_set_bnz(&aa, a);
    bnz_set_bnz(&bb, b);

    while (bnz_cmp_i32(&bb, 0) == 1) {
        if (bnz_bit_set(&bb, 0)) {
            bnz_multiply_bnz(res, res, &aa);
            bnz_mod_bnz(res, res, c);
        }
        bnz_multiply_bnz(&aa, &aa, &aa);
        bnz_mod_bnz(&aa, &aa, c);
        bnz_shift_r(&bb, 1);
    }

    bnz_free(&aa);
    bnz_free(&bb);
}

void bnz_modular_multiplicative_inverse(bnz_t *res, const bnz_t *a, const bnz_t *b) // get res where (res * a) mod b = 1, code adapted from the pseudocode of various examples of the extended Euclidean algorithm
{
    bnz_t q, rem, tmp1, t, new_t, r, new_r, tmp2;

    bnz_init(&q);
    bnz_init(&rem);
    bnz_init(&t);
    bnz_init(&new_t);
    bnz_init(&r);
    bnz_init(&new_r);
    bnz_init(&tmp1);
    bnz_init(&tmp2);

    bnz_set_i32(&t, 0);
    bnz_set_i32(&new_t, 1);
    bnz_set_bnz(&r, b);
    bnz_set_bnz(&new_r, a);

    while (!bnz_is_zero(&new_r)) {
        bnz_divide_bnz(&q, &rem, &r, &new_r);
        bnz_set_bnz(&tmp1, &new_t);
        bnz_multiply_bnz(&tmp2, &q, &tmp1);
        bnz_subtract_bnz(&new_t, &t, &tmp2);
        bnz_set_bnz(&t, &tmp1);
        bnz_set_bnz(&tmp1, &new_r);
        bnz_multiply_bnz(&tmp2, &q, &tmp1);
        bnz_subtract_bnz(&new_r, &r, &tmp2);
        bnz_set_bnz(&r, &tmp1);
    }

    if (bnz_cmp_i32(&r, 1) == 1) {
        bnz_set_i32(res, 0);
    } else {
        if (t.sign) bnz_add_bnz(&t, &t, b);
        bnz_set_bnz(res, &t);
    }

    bnz_free(&q);
    bnz_free(&rem);
    bnz_free(&t);
    bnz_free(&new_t);
    bnz_free(&r);
    bnz_free(&new_r);
    bnz_free(&tmp1);
    bnz_free(&tmp2);
}

/* SECP256K1 */

typedef struct {
    bnz_t x;
    bnz_t y;
} PT;

typedef struct {
    bnz_t p;
    bnz_t a;
    bnz_t b;
    PT G;
    bnz_t n;
    bnz_t h;
} SECP256K1;

SECP256K1 secp256k1_init(void);
void secp256k1_free(SECP256K1);
void secp256k1_point_doubling(const SECP256K1, const PT *, PT *);
void secp256k1_point_addition(const SECP256K1, PT *, PT *, PT *);
void secp256k1_scalar_multiplication(const SECP256K1, const bnz_t *, PT *);

SECP256K1 secp256k1_init() // initiate secp256k1 curve, y^2 = (x^3 + 7) mod secp256k1.p
{
    SECP256K1 secp256k1;

    bnz_init(&secp256k1.p);
    bnz_init(&secp256k1.a);
    bnz_init(&secp256k1.b);
    bnz_init(&secp256k1.G.x);
    bnz_init(&secp256k1.G.y);
    bnz_init(&secp256k1.n);
    bnz_init(&secp256k1.h);

    bnz_set_str(&secp256k1.p , "115792089237316195423570985008687907853269984665640564039457584007908834671663", 10); // prime
    bnz_set_i32(&secp256k1.a, 0);
    bnz_set_i32(&secp256k1.b, 7);
    bnz_set_str(&secp256k1.G.x, "55066263022277343669578718895168534326250603453777594175500187360389116729240", 10); // generator x
    bnz_set_str(&secp256k1.G.y, "32670510020758816978083085130507043184471273380659243275938904335757337482424", 10); // generator y
    bnz_set_str(&secp256k1.n, "115792089237316195423570985008687907852837564279074904382605163141518161494337", 10); // order
    bnz_set_i32(&secp256k1.h, 1);

    return secp256k1;
}

void secp256k1_free(SECP256K1 secp256k1) // free secp256k1 curve
{
    bnz_free(&secp256k1.p);
    bnz_free(&secp256k1.a);
    bnz_free(&secp256k1.b);
    bnz_free(&secp256k1.G.x);
    bnz_free(&secp256k1.G.y);
    bnz_free(&secp256k1.n);
    bnz_free(&secp256k1.h);
}

void secp256k1_point_doubling(const SECP256K1 secp256k1, const PT *p, PT *r) // r = 2p mod secp256k1.p
{
    bnz_t slope, tmp;

    bnz_init(&tmp);
    bnz_init(&slope);

    if (!bnz_is_zero(&p->y)) {
        bnz_multiply_i32(&tmp, &p->y, 2);
        bnz_modular_multiplicative_inverse(&tmp, &tmp, &secp256k1.p);
        bnz_multiply_bnz(&slope, &p->x, &p->x);
        bnz_multiply_i32(&slope, &slope, 3);
        bnz_add_bnz(&slope, &slope, &secp256k1.a);
        bnz_multiply_bnz(&slope, &slope, &tmp);
        bnz_mod_bnz(&slope, &slope, &secp256k1.p);
        bnz_multiply_bnz(&r->x, &slope, &slope);
        bnz_subtract_bnz(&r->x, &r->x, &p->x);
        bnz_subtract_bnz(&r->x, &r->x, &p->x);
        bnz_mod_bnz(&r->x, &r->x, &secp256k1.p);
        bnz_subtract_bnz(&tmp, &p->x, &r->x);
        bnz_multiply_bnz(&r->y, &slope, &tmp);
        bnz_subtract_bnz(&r->y, &r->y, &p->y);
        bnz_mod_bnz(&r->y, &r->y, &secp256k1.p);
    } else {
        bnz_set_i32(&r->x, 0);
        bnz_set_i32(&r->y, 0);
    }

    bnz_free(&tmp);
    bnz_free(&slope);
}

void secp256k1_point_addition(const SECP256K1 secp256k1, PT *p, PT *q, PT *r) // r = (p + q) mod secp256k1.p
{
    bnz_t tmp, slope;

    bnz_init(&tmp);
    bnz_init(&slope);

    bnz_set_i32(&slope, 0);

    bnz_mod_bnz(&p->x, &p->x, &secp256k1.p);
    bnz_mod_bnz(&p->y, &p->y, &secp256k1.p);
    bnz_mod_bnz(&q->x, &q->x, &secp256k1.p);
    bnz_mod_bnz(&q->y, &q->y, &secp256k1.p);

    if (bnz_is_zero(&p->x) && bnz_is_zero(&p->y)) {
        bnz_set_bnz(&r->x, &q->x);
        bnz_set_bnz(&r->y, &q->y);
        bnz_free(&tmp);
        bnz_free(&slope);
        return;
    }

    if (bnz_is_zero(&q->x) && bnz_is_zero(&q->y)) {
        bnz_set_bnz(&r->x, &p->x);
        bnz_set_bnz(&r->y, &p->y);
        bnz_free(&tmp);
        bnz_free(&slope);
        return;
    }

    if (!bnz_is_zero(&q->y)) {
        bnz_subtract_bnz(&tmp, &secp256k1.p, &q->y);
        bnz_mod_bnz(&tmp, &tmp, &secp256k1.p);
    } else {
        bnz_set_i32(&tmp, 0);
    }

    if (bnz_cmp_bnz(&p->y, &tmp) == 0 && bnz_cmp_bnz(&p->x, &q->x) == 0) {
        bnz_set_i32(&r->x, 0);
        bnz_set_i32(&r->y, 0);
        bnz_free(&tmp);
        bnz_free(&slope);
        return;
    }

    if (bnz_cmp_bnz(&p->x, &q->x) == 0 && bnz_cmp_bnz(&p->y, &q->y) == 0) {
        secp256k1_point_doubling(secp256k1, p, r);
    } else {
        bnz_subtract_bnz(&tmp, &p->x, &q->x);
        bnz_mod_bnz(&tmp, &tmp, &secp256k1.p);
        bnz_modular_multiplicative_inverse(&tmp, &tmp, &secp256k1.p);
        bnz_subtract_bnz(&slope, &p->y, &q->y);
        bnz_multiply_bnz(&slope, &slope, &tmp);
        bnz_mod_bnz(&slope, &slope, &secp256k1.p);
        bnz_multiply_bnz(&r->x, &slope, &slope);
        bnz_subtract_bnz(&r->x, &r->x, &p->x);
        bnz_subtract_bnz(&r->x, &r->x, &q->x);
        bnz_mod_bnz(&r->x, &r->x, &secp256k1.p);
        bnz_subtract_bnz(&tmp, &p->x, &r->x);
        bnz_multiply_bnz(&r->y, &slope, &tmp);
        bnz_subtract_bnz(&r->y, &r->y, &p->y);
        bnz_mod_bnz(&r->y, &r->y, &secp256k1.p);
    }

    bnz_free(&tmp);
    bnz_free(&slope);
}

void secp256k1_scalar_multiplication(const SECP256K1 secp256k1, const bnz_t *m, PT *r) // r = (secp256k1.G * m) mod secp256k1.p
{
    size_t i, bits = 8 * m->size;

    PT q, tmp;

    bnz_init(&q.x);
    bnz_init(&q.y);
    bnz_init(&tmp.x);
    bnz_init(&tmp.y);

    bnz_set_i32(&r->x, 0);
    bnz_set_i32(&r->y, 0);

    if (bnz_is_zero(m)) {
        bnz_free(&q.x);
        bnz_free(&q.y);
        bnz_free(&tmp.x);
        bnz_free(&tmp.y);
        return;
    }

    bnz_set_bnz(&q.x, &secp256k1.G.x);
    bnz_set_bnz(&q.y, &secp256k1.G.y);

    if (bnz_bit_set(m, 0) == 1) {
        bnz_set_bnz(&r->x, &secp256k1.G.x);
        bnz_set_bnz(&r->y, &secp256k1.G.y);
    }

    for (i = 1; i < bits; i++) {
        bnz_set_i32(&tmp.x, 0);
        bnz_set_i32(&tmp.y, 0);
        secp256k1_point_doubling(secp256k1, &q, &tmp);
        bnz_set_bnz(&q.x, &tmp.x);
        bnz_set_bnz(&q.y, &tmp.y);
        bnz_set_bnz(&tmp.x, &r->x);
        bnz_set_bnz(&tmp.y, &r->y);
        if (bnz_bit_set(m, i)) secp256k1_point_addition(secp256k1, &tmp, &q, r);
    }

    bnz_free(&q.x);
    bnz_free(&q.y);
    bnz_free(&tmp.x);
    bnz_free(&tmp.y);
}

/* BITCOIN */

uint8_t *get_salt(const char *);
void get_ripemd160_sha256(bnz_t *, const bnz_t *, size_t);
void get_sha256_sha256(bnz_t *, const bnz_t *, size_t);
void bnz_256_bit_rnd(bnz_t *);
void entropy_checksum(bnz_t *);
void get_bip39_word_ids_bnz(bnz_t *, uint32_t *);
void get_bip39_word_ids_str(bnz_t *, bnz_t *, uint8_t *, char *);
uint8_t *get_mnemonic_phrase(uint32_t *);
void get_seed_from_mnemonic_phrase(bnz_t *, const char *, const char *);
void get_master_keys(bnz_t *, bnz_t *, const bnz_t *);
void get_child_normal(bnz_t *, bnz_t *, const bnz_t *, const bnz_t *, const bnz_t *, uint32_t);
void get_child_hardened(bnz_t *, bnz_t *, const bnz_t *, const bnz_t *, uint32_t);
void get_hdk_intermediate_values(const bnz_t *, const bnz_t *, char *);
void get_public_key_compressed(bnz_t *, bnz_t *);
void get_public_key(PT *, bnz_t *, bnz_t *);
void get_public_key_xy(PT *, bnz_t *);
void get_random_master_keys(bnz_t *, bnz_t *, bnz_t *);
void get_wallet_p2pkh_addresses(bnz_t *, bnz_t *);
void get_wallet_p2wpkh_addresses(bnz_t *, bnz_t *);
void get_p2pkh_address(bnz_t *, bnz_t *);
void get_xprv_master(bnz_t *, bnz_t *, bnz_t *);
void get_xpub_master(bnz_t *, bnz_t *, bnz_t *);
void get_xprv_child(bnz_t *, uint8_t, uint32_t, bnz_t *, bnz_t *, bnz_t *);
void get_xpub_child(bnz_t *, uint8_t, uint32_t, bnz_t *, bnz_t *, bnz_t *);
void get_segwit_p2wpkh_address(bnz_t *, const bnz_t *);
uint32_t segwit_p2wpkh_checksum_update(uint32_t, uint8_t);
void print_segwit_p2wpkh_address(const bnz_t *, const uint8_t *);

uint8_t *get_salt(const char *passphrase) // generate salt string from passphrase
{
    uint8_t *salt = NULL;
    if (!(salt = init_uint8_array(strlen(passphrase) + 12))) return NULL; // strlen(passphrase) + strlen("mnemonic") + sizeof(uint32_t)
    sprintf(salt, "mnemonic%s", passphrase); // concatenate "mnemonic" with passphrase string, plus 4 zero bytes
    salt[strlen(passphrase) + 11] = 1; // last 4 bytes = 1 formatted as uint32_t
    return salt;
}

void get_ripemd160_sha256(bnz_t *res, const bnz_t *a, size_t len) // res = first len bytes of ripemd160(sha256(a.digits)) as a bnz_t
{
    uint8_t h1[32], h2[20];
    bnz_t aa; // aa is a mutable local copy of a 
    bnz_init(&aa); // initiate aa
    bnz_set_bnz(&aa, a); // set aa = a, standard little endian order
    bnz_reverse_digits(&aa); // convert aa.digits to big endian order
    sha256(aa.digits, aa.size, h1); // h1 = sha256(aa.digits)
    ripemd160(h1, 32, h2); // h2 = ripemd160(sha256(aa.digits))
    bnz_resize(res, len, 0); // prepare res.digits to receive first len bytes of h2
    memcpy(res->digits, h2, len); // copy first len bytes of h2 into res.digits, big endian order
    bnz_reverse_digits(res); // convert res.digits to standard bnz_t little endian order
    bnz_free(&aa); // free aa resources
}

void get_sha256_sha256(bnz_t *res, const bnz_t *a, size_t len) // res = first len bytes of sha256(sha256(a.digits)) as a bnz_t
{
    uint8_t h1[32], h2[32];
    bnz_t aa; // aa is a mutable local copy of a
    bnz_init(&aa); // initiate aa
    bnz_set_bnz(&aa, a); // set aa = a, standard little endian order
    bnz_reverse_digits(&aa); // convert aa.digits to big endian order
    sha256(aa.digits, aa.size, h1); // h1 = sha256(aa.digits)
    sha256(h1, 32, h2); // h2 = sha256(sha256(aa.digits))
    bnz_resize(res, len, 0); // prepare res.digits to receive the first len bytes of h2
    memcpy(res->digits, h2, len); // copy first len bytes of h2 into res.digits, big endian order
    bnz_reverse_digits(res); // convert res.digits to standard bnz_t little endian order
    bnz_free(&aa); // free aa resources
}

void bnz_256_bit_rnd(bnz_t *rnd) // generate pseudo random 256 bit entropy as a bnz_t
{
    uint32_t random;
    size_t i;
    bnz_resize(rnd, 32, 0);
    for (i = 0; i < 32; i++) {
        rand_s(&random); // on non-Windows systems, change this to some other source of cryptographically secure random numbers
        rnd->digits[i] = random & 255; // rnd->digits[i] = last byte of random
    }
}

void entropy_checksum(bnz_t *entropy) // append checksum byte to the lsb end of 256 bits of entropy as a bnz_t
{
    uint8_t sha256_digest[32];
    bnz_t tmp; // tmp = local mutable copy of entropy
    bnz_init(&tmp); // initiate tmp

    bnz_set_bnz(&tmp, entropy); // copy entropy into tmp
    bnz_resize(&tmp, 32, 1); // ensure that tmp is 32 bytes
    bnz_reverse_digits(&tmp); // convert tmp.digits to big endian order
    sha256(tmp.digits, tmp.size, sha256_digest); // sha256_digest = sha256[tmp.digits]

    bnz_concatenate_ui8(&tmp, &tmp, sha256_digest[0], 0); // concatenate first byte of sha256_digest the the lsb end of tmp
    bnz_reverse_digits(&tmp); // convert tmp.digits to standard little endian order
    
    bnz_set_bnz(entropy, &tmp); // copy tmp back into entropy
    bnz_free(&tmp); // free tmp resources
}

void get_bip39_word_ids_bnz(bnz_t *entropy_chk, uint32_t *wd_ids) // convert 33 bytes of entropy + checksum as a bnz_t into 24 numbers of 11 bits
{
    size_t i;
    bnz_t tmp;
    bnz_init(&tmp);

    bnz_set_bnz(&tmp, entropy_chk);
    bnz_resize(&tmp, 33, 1);
    bnz_reverse_digits(&tmp);

    for (i = 0; i < 3; i++) {
        wd_ids[(i * 8) + 0] = ((((uint32_t)tmp.digits[(i * 11) + 0]) << 3) & 2040) + ((((uint32_t)tmp.digits[(i * 11) + 1]) >> 5) & 7);
        wd_ids[(i * 8) + 1] = ((((uint32_t)tmp.digits[(i * 11) + 1]) << 6) & 1984) + ((((uint32_t)tmp.digits[(i * 11) + 2]) >> 2) & 63);
        wd_ids[(i * 8) + 2] = ((((uint32_t)tmp.digits[(i * 11) + 2]) << 9) & 1536) + ((((uint32_t)tmp.digits[(i * 11) + 3]) << 1) & 510) + ((((uint32_t)tmp.digits[(i * 11) + 4]) >> 7) & 1);
        wd_ids[(i * 8) + 3] = ((((uint32_t)tmp.digits[(i * 11) + 4]) << 4) & 2032) + ((((uint32_t)tmp.digits[(i * 11) + 5]) >> 4) & 15);
        wd_ids[(i * 8) + 4] = ((((uint32_t)tmp.digits[(i * 11) + 5]) << 7) & 1920) + ((((uint32_t)tmp.digits[(i * 11) + 6]) >> 1) & 127);
        wd_ids[(i * 8) + 5] = ((((uint32_t)tmp.digits[(i * 11) + 6]) << 10) & 1024) + ((((uint32_t)tmp.digits[(i * 11) + 7]) << 2) & 2044) + ((((uint32_t)tmp.digits[(i * 11) + 8]) >> 6) & 3);
        wd_ids[(i * 8) + 6] = ((((uint32_t)tmp.digits[(i * 11) + 8]) << 5) & 2016) + ((((uint32_t)tmp.digits[(i * 11) + 9]) >> 3) & 31);
        wd_ids[(i * 8) + 7] = ((((uint32_t)tmp.digits[(i * 11) + 9]) << 8) & 1792) + ((((uint32_t)tmp.digits[(i * 11) + 10])));
    }

    bnz_free(&tmp);
}

void get_bip39_word_ids_str(bnz_t *entropy_chk, bnz_t *entropy, uint8_t *chk, char *mnemonic_str) // convert 24 words into 32 bytes of entropy + 1 byte of checksum
{
    size_t i = 0, j;
    char sha256_digest[32], *tok = strtok(mnemonic_str, " "); // split mnemonic string into an array of BIP39 words
    uint32_t wd_ids[24];

    bnz_resize(entropy_chk, 33, 0);

    while (tok != NULL) { // traverse array
        for (j = 0; j < 2048; j++) { // search BIP39 list for matches
            if (!strcmp(tok, bip39_wds[j])) { // match found
                wd_ids[i++] = j; // record id
                break; // exit loop as soon as match found
            }
        }
        tok = strtok(NULL, " "); // next array member
    }

    for (i = 0; i < 3; i++) {
        entropy_chk->digits[(i * 11) + 0] = (wd_ids[(i * 8) + 0] >> 3) & 255;
        entropy_chk->digits[(i * 11) + 1] = ((wd_ids[(i * 8) + 0] & 7) << 5) + (wd_ids[(i * 8) + 1] >> 6) & 255;
        entropy_chk->digits[(i * 11) + 2] = ((wd_ids[(i * 8) + 1] & 63) << 2) + (wd_ids[(i * 8) + 2] >> 9) & 255;
        entropy_chk->digits[(i * 11) + 3] = (wd_ids[(i * 8) + 2] >> 1) & 255;
        entropy_chk->digits[(i * 11) + 4] = ((wd_ids[(i * 8) + 2] & 1) << 7) + (wd_ids[(i * 8) + 3] >> 4) & 255;
        entropy_chk->digits[(i * 11) + 5] = ((wd_ids[(i * 8) + 3] & 15) << 4) + (wd_ids[(i * 8) + 4] >> 7) & 255;
        entropy_chk->digits[(i * 11) + 6] = ((wd_ids[(i * 8) + 4] & 127) << 1) + (wd_ids[(i * 8) + 5] >> 10) & 255;
        entropy_chk->digits[(i * 11) + 7] = (wd_ids[(i * 8) + 5] >> 2) & 255;
        entropy_chk->digits[(i * 11) + 8] = ((wd_ids[(i * 8) + 5] & 3) << 6) + (wd_ids[(i * 8) + 6] >> 5) & 255;
        entropy_chk->digits[(i * 11) + 9] = ((wd_ids[(i * 8) + 6] & 31) << 3) + (wd_ids[(i * 8) + 7] >> 8) & 255;
        entropy_chk->digits[(i * 11) + 10] = wd_ids[(i * 8) + 7] & 255;
    }

    bnz_set_bnz(entropy, entropy_chk); // copy 33 bytes of entropy_chk into entropy
    bnz_resize(entropy, 32, 1); // resize entropy to 32 bytes of entropy
    sha256(entropy->digits, 32, sha256_digest); // get SHA256 hash digest of entropy->digits
    *chk = sha256_digest[0]; // set chk to first byte of SHA256 hash digest
    bnz_reverse_digits(entropy); // convert to little
    bnz_reverse_digits(entropy_chk); // endian order
}

uint8_t *get_mnemonic_phrase(uint32_t *wd_ids) // generate mnemonic string of 24 words
{
    uint8_t *mnemonic_str = NULL;
    int i, len = 0;
    for (i = 0; i < 24; i++) {
        len += strlen(bip39_wds[wd_ids[i]]);
    }
    if (!(mnemonic_str = init_uint8_array(len + 24 /* 23 chars for the spaces between the individual mnemonic words + one char for the null terminus */))) return NULL;
    for (i = 0; i < 23; i++) {
        sprintf(mnemonic_str + strlen(mnemonic_str), "%s ", bip39_wds[wd_ids[i]]);
    }
    sprintf(mnemonic_str + strlen(mnemonic_str), "%s", bip39_wds[wd_ids[23]]);
    return(mnemonic_str);
}

void get_seed_from_mnemonic_phrase(bnz_t *seed, const char *mnemonic, const char *passphrase) // generate 64 byte seed from mnemonic string and optional passphrase
{
    uint8_t tmp[64], *salt = NULL;
    size_t i, j;
    bnz_resize(seed, 64, 0); // ensure that seed is 64 bytes
    if (!(salt = get_salt(passphrase))) return; // salt = "mnemonic" concatenated with passphrase, strlen(salt) = strlen(passphrase) + strlen("mnemonic") + 4 bytes of uint32_t
    hmac_sha512(mnemonic, strlen(mnemonic), salt, strlen(passphrase) + 12, tmp, 64); // tmp = first hmac(mnemonic, salt)
    memcpy(seed->digits, tmp, 64); // set seed = result of first hmac process
    for (i = 1; i < 2048; i++) {
        hmac_sha512(mnemonic, strlen(mnemonic), tmp, 64, tmp, 64);  // tmp = hmac(mnemonic, tmp), 2048 times
        for (j = 0; j < 64; j++) {
            seed->digits[j] = tmp[j] ^ seed->digits[j]; // xor current each byte of seed.digits with corresponding byte of current tmp
        }
    }
    bnz_reverse_digits(seed); // convert seed.digits to standard little endian order
    free(salt); // free resources
}

void get_master_keys(bnz_t *master_private_key, bnz_t *master_chain_code, const bnz_t *seed) // generate 32 byte master private key and 32 byte master chain_code
{
    uint8_t mac[64];

    bnz_t tmp;
    bnz_init(&tmp);

    bnz_set_bnz(&tmp, seed); // copy seed to tmp

    bnz_resize(&tmp, 64, 1); // ensure that tmp is 64 bytes
    bnz_reverse_digits(&tmp); // convert tmp.digits to big endian order
    hmac_sha512("Bitcoin seed", 12, tmp.digits, tmp.size, mac, 64); // generate 64 byte MAC from tmp.digits and the initial key "Bitcoin seed"

    bnz_resize(master_private_key, 32, 0); // prepare master_private_key to receive the first 32 bytes of the MAC
    memcpy(master_private_key->digits, mac, 32); // copy the first 32 bytes of the MAC into master_private_key
    bnz_reverse_digits(master_private_key); // convert master_private_key.digits to default little endian order

    bnz_resize(master_chain_code, 32, 0); // prepare master_chain_code to receive the last 32 bytes of the MAC
    memcpy(master_chain_code->digits, mac + 32, 32); // copy the last 32 bytes of the MAC into master_chain_code
    bnz_reverse_digits(master_chain_code); // convert master_chain_code.digits to default little endian order

    bnz_free(&tmp);
}

void get_child_normal(bnz_t *child_private_key, bnz_t *child_chain_code, const bnz_t *parent_private_key, const bnz_t *parent_chain_code, const bnz_t *parent_public_key_compressed, uint32_t index_num)
{
    uint8_t mac[64];
    bnz_t index, tmp1, tmp2;
    SECP256K1 secp256k1;

    bnz_init(&index);
    bnz_init(&tmp1);
    bnz_init(&tmp2);

    secp256k1 = secp256k1_init();

    bnz_set_ui32(&index, index_num);
    bnz_set_bnz(&tmp1, parent_chain_code);
    bnz_set_bnz(&tmp2, parent_public_key_compressed);

    bnz_resize(&index, 4, 1);
    bnz_resize(&tmp1, 32, 1);
    bnz_resize(&tmp2, 33, 1);

    bnz_concatenate_bnz(&tmp2, &tmp2, &index, 1);

    bnz_reverse_digits(&tmp1);
    bnz_reverse_digits(&tmp2);

    hmac_sha512(tmp1.digits, tmp1.size, tmp2.digits, tmp2.size, mac, 64);

    bnz_resize(child_private_key, 32, 0);
    bnz_resize(child_chain_code, 32, 0);

    memcpy(child_private_key->digits, mac, 32);
    memcpy(child_chain_code->digits, mac + 32, 32);

    bnz_reverse_digits(child_private_key);
    bnz_add_bnz(child_private_key, child_private_key, parent_private_key);
    bnz_mod_bnz(child_private_key, child_private_key, &secp256k1.n);

    bnz_reverse_digits(child_chain_code);

    bnz_free(&index);
    bnz_free(&tmp1);
    bnz_free(&tmp2);

    secp256k1_free(secp256k1);
}

void get_child_hardened(bnz_t *child_private_key, bnz_t *child_chain_code, const bnz_t *parent_private_key, const bnz_t *parent_chain_code, uint32_t index_num)
{
    uint8_t mac[64];
    bnz_t index, tmp1, tmp2;
    SECP256K1 secp256k1;

    bnz_init(&index);
    bnz_init(&tmp1);
    bnz_init(&tmp2);

    secp256k1 = secp256k1_init();

    bnz_set_ui32(&index, index_num < 2147483648 ? 2147483648 + index_num : index_num);
    bnz_set_bnz(&tmp1, parent_chain_code);
    bnz_set_bnz(&tmp2, parent_private_key);

    bnz_resize(&index, 4, 1);
    bnz_resize(&tmp1, 32, 1);
    bnz_resize(&tmp2, 32, 1);

    bnz_concatenate_ui8(&tmp2, &tmp2, 0, 0);
    bnz_concatenate_bnz(&tmp2, &tmp2, &index, 1);

    bnz_reverse_digits(&tmp1);
    bnz_reverse_digits(&tmp2);

    hmac_sha512(tmp1.digits, tmp1.size, tmp2.digits, tmp2.size, mac, 64);

    bnz_resize(child_private_key, 32, 0);
    bnz_resize(child_chain_code, 32, 0);

    memcpy(child_private_key->digits, mac, 32);
    memcpy(child_chain_code->digits, mac + 32, 32);

    bnz_reverse_digits(child_private_key);
    bnz_add_bnz(child_private_key, child_private_key, parent_private_key);
    bnz_mod_bnz(child_private_key, child_private_key, &secp256k1.n);

    bnz_reverse_digits(child_chain_code);

    bnz_free(&index);
    bnz_free(&tmp1);
    bnz_free(&tmp2);

    secp256k1_free(secp256k1);
}

void get_hdk_intermediate_values(const bnz_t *master_private_key, const bnz_t *master_chain_code, char *hdk_str)
{
    char *tok = strtok(hdk_str, "/"), display_str[32]; // split str into an array of indicies
    uint32_t index, depth = 0;
    bnz_t parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, child_public_key_compressed, child_xpub;

    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&child_xpub);

    bnz_set_bnz(&parent_private_key, master_private_key);
    bnz_set_bnz(&parent_chain_code, master_chain_code);

    sprintf(display_str, "m");

    if (strcmp(tok, "m") == 0) {
        tok = strtok(NULL, "/"); // get first array member
        while (tok != NULL) { // traverse array

            sprintf(display_str + strlen(display_str), "/"); // update display
            sprintf(display_str + strlen(display_str), tok); // string

            depth++; // increment depth
            index = atoi(tok); // extract index from tok, ignoring any "'" indicating hardened child 

            get_public_key_compressed(&parent_public_key_compressed, &parent_private_key); // get parent compressed public key for calculating normal child / xpub 

            if (tok[strlen(tok) - 1] == '\'') { // check for presence of "'" indicating hardened child
                if (index < 2147483648) index += 2147483648;
                get_child_hardened(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, index); // if last char of tok is "'", get hardened child
            } else {
                get_child_normal(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, index); // if last char of tok is not "'", get normal child
            }

            get_public_key_compressed(&child_public_key_compressed, &child_private_key); // get compressed public key from child private key
            get_xpub_child(&child_xpub, depth, index, &parent_public_key_compressed, &child_public_key_compressed, &child_chain_code); // calculate child xpub

            // print results
            printf("%s\n", display_str);
            bnz_print(&parent_private_key, 16, "PARENT PRIVATE KEY: ");
            bnz_print(&parent_chain_code, 16, "PARENT CHAIN CODE: ");
            bnz_print(&child_private_key, 16, "CHILD PRIVATE KEY: ");
            bnz_print(&child_chain_code, 16, "CHILD CHAIN CODE: ");
            bnz_print(&child_xpub, 58, "CHILD XPUB: ");
            printf("\n");

            // prepare next iteration by setting parent private key and parent chain code to current child private key and child chain code
            bnz_set_bnz(&parent_private_key, &child_private_key);
            bnz_set_bnz(&parent_chain_code, &child_chain_code);

            tok = strtok(NULL, "/"); // next array member
        }
    }

    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&child_public_key_compressed);
    bnz_free(&child_xpub);
}

void get_public_key_compressed(bnz_t *public_key_compressed, bnz_t *private_key)
{
    PT public_key;

    bnz_init(&public_key.x);
    bnz_init(&public_key.y);

    SECP256K1 secp256k1 = secp256k1_init();

    secp256k1_scalar_multiplication(secp256k1, private_key, &public_key);

    bnz_resize(&public_key.x, 32, 1);

    if (bnz_bit_set(&public_key.y, 0) == 0) {
        bnz_concatenate_ui8(public_key_compressed, &public_key.x, 2, 0);
    } else { // odd y
        bnz_concatenate_ui8(public_key_compressed, &public_key.x, 3, 0);
    }
    
    bnz_free(&public_key.x);
    bnz_free(&public_key.y);

    secp256k1_free(secp256k1);
}

void get_public_key(PT *public_key, bnz_t *public_key_compressed, bnz_t *private_key) // generate public key from private key
{
    SECP256K1 secp256k1 = secp256k1_init();

    secp256k1_scalar_multiplication(secp256k1, private_key, public_key); // public_key = (secp256k1.G * private_key) mod secp256k1.p

    bnz_resize(&public_key->x, 32, 1); // ensure that the compressed public key is 32 bytes long before concatenation with the even y / odd y byte

    if (bnz_bit_set(&public_key->y, 0) == 0) { // even y
        bnz_concatenate_ui8(public_key_compressed, &public_key->x, 2, 0); // prepend 2
    } else { // odd y
        bnz_concatenate_ui8(public_key_compressed, &public_key->x, 3, 0); // prepend 3
    }
    
    secp256k1_free(secp256k1);
}

void get_public_key_xy(PT *public_key, bnz_t *public_key_compressed) // regenerate public key point on secp256k1 from compressed public key
{
    uint8_t typ = public_key_compressed->digits[public_key_compressed->size - 1]; // byte at msb encodes the parity of y: typ = 0x02 for even y, typ = 0x03 for odd y
    bnz_t exp, y_sq;
    SECP256K1 secp256k1;

    bnz_init(&exp);
    bnz_init(&y_sq);

    secp256k1 = secp256k1_init();

    /*

    In this function we wish to regenerate the x,y coordinates of a point on secp256k1 from a compressed public key, which is
    the x coordinate of the point concatenated (at the msb end) with a byte of value 2 or 3, depending on whether the value of
    y is even (0x02) or odd (0x03).

    Generating the y coordinate of a point on secp256k1, given the corresponding x coordinate, leverages a nice property of secp256k1
    which is that, given y^2 mod secp256k1.p (easily calculated from x given the formula of secp256k1: y^2 = x^3 + 7), we can
    calculate y as follows:

        y mod secp256k1.p = (y_sq^((secp256k1.p + 1) / 4)) mod secp256k1.p

    In this function we use a pre-calculated value of (secp256k1.p + 1) / 4.

    */
    bnz_set_str(&exp, "28948022309329048855892746252171976963317496166410141009864396001977208667916", 10); // (secp256k1.p + 1) / 4

    bnz_set_bnz(&public_key->x, public_key_compressed); // public_key.x = compressed public key
    bnz_resize(&public_key->x, public_key->x.size - 1, 1); // public_key.x = decompressed public key, byte at msb end removed

    bnz_set_bnz(&y_sq, &public_key->x); // y_sq = public_key.x
    bnz_multiply_bnz(&y_sq, &y_sq, &public_key->x); // y_sq = public_key.x^2
    bnz_multiply_bnz(&y_sq, &y_sq, &public_key->x); // y_sq = public_key.x^3
    bnz_add_i32(&y_sq, &y_sq, 7); // y_sq = public_key.x^3 + 7
    bnz_mod_bnz(&y_sq, &y_sq, &secp256k1.p); // y_sq mod secp256k1.p = (public_key.x^3 + 7) mod secp256k1.p

    bnz_mod_pow(&public_key->y, &y_sq, &exp, &secp256k1.p); // y mod secp256k1.p = (y_sq^((secp256k1.p + 1) / 4)) mod secp256k1.p

    if ((typ == 2 && bnz_bit_set(&public_key->y, 0) == 1) || (typ == 3 && bnz_bit_set(&public_key->y, 0) == 0)) { // mismatched typ and y
        bnz_subtract_bnz(&public_key->y, &secp256k1.p, &public_key->y); // y = secp256k1.p - y, negation of y mod p
    }

    bnz_free(&exp);
    bnz_free(&y_sq);

    secp256k1_free(secp256k1);
}

void get_random_master_keys(bnz_t *entropy, bnz_t *master_private_key, bnz_t *master_chain_code) // NOT SECURE use random 256 bit entropy to generate master private key and master chain code
{
    char *mnemonic = NULL;
    uint32_t wd_ids[24];
    bnz_t tmp, seed;

    bnz_init(&tmp);
    bnz_init(&seed);

    bnz_256_bit_rnd(entropy); // generate 32 bytes of random entropy
    bnz_set_bnz(&tmp, entropy); // copy entropy into tmp

    entropy_checksum(&tmp); // calculate and append checksum byte to copy of entropy, 33 byte result
    get_bip39_word_ids_bnz(&tmp, wd_ids); // get the ids of the 24 BIP39 words from the 33 byte tmp
    mnemonic = get_mnemonic_phrase(wd_ids); // generate mnemonic phrase string from BIP39 word ids
    get_seed_from_mnemonic_phrase(&seed, mnemonic, ""); // generate 64 byte seed from mnemonic phrase
    get_master_keys(master_private_key, master_chain_code, &seed); // generate master private key and master chain code from seed

    free(mnemonic);
    bnz_free(&tmp);
    bnz_free(&seed);
}

void get_wallet_p2pkh_addresses(bnz_t *master_private_key, bnz_t *master_chain_code)
{
    uint32_t i;
    
    bnz_t parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, child_public_key_compressed, p2pkh;

    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&p2pkh);

    // m/44'
    bnz_set_bnz(&parent_private_key, master_private_key);
    bnz_set_bnz(&parent_chain_code, master_chain_code);
    get_child_hardened(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 44);

    // m/44'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/44'/0'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/44'/0'/0'/0
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(&parent_public_key_compressed, &parent_private_key);
    get_child_normal(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, 0);

    // m/44'/0'/0'/0/0 to m/44'/0'/0'/0/19
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(&parent_public_key_compressed, &parent_private_key);
    for (i = 0; i < 20; i++) {
        get_child_normal(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, i);
        get_public_key_compressed(&child_public_key_compressed, &child_private_key);
        get_p2pkh_address(&p2pkh, &child_public_key_compressed);
        printf("m/44'/0'/0'/0/%d: ", i);
        bnz_print(&p2pkh, 58, "1");
    }

    printf("\n");

    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&p2pkh);
}

void get_wallet_p2wpkh_addresses(bnz_t *master_private_key,bnz_t *master_chain_code)
{
    uint32_t i;
    
    bnz_t parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, child_public_key_compressed, p2wpkh;

    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&p2wpkh);

    // m/84'
    bnz_set_bnz(&parent_private_key, master_private_key);
    bnz_set_bnz(&parent_chain_code, master_chain_code);
    get_child_hardened(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 84);

    // m/84'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/84'/0'/0'
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_child_hardened(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, 0);

    // m/84'/0'/0'/0
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(&parent_public_key_compressed, &parent_private_key);
    get_child_normal(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, 0);

    // m/84'/0'/0'/0/0 to m/84'/0'/0'/0/19
    bnz_set_bnz(&parent_private_key, &child_private_key);
    bnz_set_bnz(&parent_chain_code, &child_chain_code);
    get_public_key_compressed(&parent_public_key_compressed, &parent_private_key);
    for (i = 0; i < 20; i++) {
        get_child_normal(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, i);
        get_public_key_compressed(&child_public_key_compressed, &child_private_key);
        get_segwit_p2wpkh_address(&p2wpkh, &child_public_key_compressed);
        printf("m/84'/0'/0'/0/%d: ", i);
        print_segwit_p2wpkh_address(&p2wpkh, "");
    }
    printf("\n");

    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&p2wpkh);
}

void get_xprv_master(bnz_t *xprv, bnz_t *master_private_key, bnz_t *master_chain_code)
{
    bnz_t chk;
    bnz_init(&chk);

    bnz_resize(master_private_key, 32, 1); // ensure master_private_key is 32 bytes
    bnz_resize(master_chain_code, 32, 1); // ensure master_chain_code is 32 bytes

    bnz_set_str(xprv, "0488ade4000000000000000000", 16); // 0x0488ade4 + 9 zero bytes: depth (1 byte), index (4 bytes), and parent public key hash fingerprint (4 bytes) are all 0 
    bnz_concatenate_bnz(xprv, xprv, master_chain_code, 1); // append master_chain_code at lsb end
    bnz_concatenate_ui8(xprv, xprv, 0, 1); // append 0x0 before master_private_key at lsb  end
    bnz_concatenate_bnz(xprv, xprv, master_private_key, 1); // append master master_private_key at lsb end
    get_sha256_sha256(&chk, xprv, 4); // get 4 byte checksum
    bnz_concatenate_bnz(xprv, xprv, &chk, 1); // append checksum at lsb end

    bnz_free(&chk);
}

void get_xpub_master(bnz_t *xpub, bnz_t *master_public_key_compressed, bnz_t *master_chain_code)
{
    bnz_t chk;
    bnz_init(&chk);

    bnz_resize(master_public_key_compressed, 33, 1); // ensure master_public_key_compressed is 33 bytes
    bnz_resize(master_chain_code, 32, 1); // ensure master_chain_code is 32 bytes

    bnz_set_str(xpub, "0488b21e000000000000000000", 16); // 0x0488b21e + 9 zero bytes: depth (1 byte), index (4 bytes), and parent public key hash fingerprint (4 bytes) are all 0 
    bnz_concatenate_bnz(xpub, xpub, master_chain_code, 1); // append master_chain_code at lsb end
    bnz_concatenate_bnz(xpub, xpub, master_public_key_compressed, 1); // append master_public_key_compressed at lsb end
    get_sha256_sha256(&chk, xpub, 4); // get 4 byte checksum
    bnz_concatenate_bnz(xpub, xpub, &chk, 1); // append checksum at lsb end

    bnz_free(&chk);
}

void get_xprv_child(bnz_t *xprv, uint8_t depth_num, uint32_t index_num, bnz_t *parent_public_key_compressed, bnz_t *child_private_key, bnz_t *child_chain_code)
{
    bnz_t chk, index, parent_public_key_hash_fingerprint;
    bnz_init(&chk);
    bnz_init(&index);
    bnz_init(&parent_public_key_hash_fingerprint);

    bnz_set_ui32(&index, index_num);

    get_ripemd160_sha256(&parent_public_key_hash_fingerprint, parent_public_key_compressed, 4); // parent_public_key_hash_fingerprint = first 4 bytes of ripemd160(sha256(parent_public_key_compressed))

    bnz_resize(&index, 4, 1); // ensure index is four bytes
    bnz_resize(child_private_key, 32, 1); // ensure child_private_key is 32 bytes
    bnz_resize(child_chain_code, 32, 1); // ensure child_chain_code is 32 bytes

    bnz_set_str(xprv, "0488ade4", 16); // 0x0488ade4
    bnz_concatenate_ui8(xprv, xprv, depth_num, 1); // append depth byte at lsb end
    bnz_concatenate_bnz(xprv, xprv, &parent_public_key_hash_fingerprint, 1); // append four byte parent_public_key_hash_fingerprint at lsb end
    bnz_concatenate_bnz(xprv, xprv, &index, 1); // append four byte index at lsb end
    bnz_concatenate_bnz(xprv, xprv, child_chain_code, 1); // append 32 byte child_chain_code at lsb end
    bnz_concatenate_ui8(xprv, xprv, 0, 1); // append 0x0 before child_private_key at lsb  end
    bnz_concatenate_bnz(xprv, xprv, child_private_key, 1); // append 32 byte child_private_key at lsb end
    get_sha256_sha256(&chk, xprv, 4); // get 4 byte checksum
    bnz_concatenate_bnz(xprv, xprv, &chk, 1); // append checksum at lsb end

    bnz_free(&chk);
    bnz_free(&index);
    bnz_free(&parent_public_key_hash_fingerprint);
}

void get_xpub_child(bnz_t *xprv, uint8_t depth_num, uint32_t index_num, bnz_t *parent_public_key_compressed, bnz_t *child_public_key_compressed, bnz_t *child_chain_code)
{
    bnz_t chk, index, parent_public_key_hash_fingerprint;
    bnz_init(&chk);
    bnz_init(&index);
    bnz_init(&parent_public_key_hash_fingerprint);

    bnz_set_ui32(&index, index_num);

    get_ripemd160_sha256(&parent_public_key_hash_fingerprint, parent_public_key_compressed, 4);

    bnz_resize(&index, 4, 1); // ensure index is four bytes
    bnz_resize(child_public_key_compressed, 33, 1); // ensure child_public_key_compressed is 33 bytes
    bnz_resize(child_chain_code, 32, 1); // ensure child_chain_code is 32 bytes

    bnz_set_str(xprv, "0488b21e", 16); // 0x0488b21e
    bnz_concatenate_ui8(xprv, xprv, depth_num, 1); // append depth byte at lsb end
    bnz_concatenate_bnz(xprv, xprv, &parent_public_key_hash_fingerprint, 1); // append four byte parent_public_key_hash_fingerprint at lsb end
    bnz_concatenate_bnz(xprv, xprv, &index, 1); // append four byte index at lsb end
    bnz_concatenate_bnz(xprv, xprv, child_chain_code, 1); // append 32 byte child_chain_code at lsb end
    bnz_concatenate_bnz(xprv, xprv, child_public_key_compressed, 1); // append 33 byte child_public_key_compressed at lsb end
    get_sha256_sha256(&chk, xprv, 4); // get 4 byte checksum
    bnz_concatenate_bnz(xprv, xprv, &chk, 1); // append checksum at lsb end

    bnz_free(&chk);
    bnz_free(&index);
    bnz_free(&parent_public_key_hash_fingerprint);
}

void get_p2pkh_address(bnz_t *p2pkh, bnz_t *public_key_compressed) // get p2pkh address from compressed public key
{
    bnz_t fingerprint;
    bnz_init(&fingerprint);
    get_ripemd160_sha256(p2pkh, public_key_compressed, 20); // set p2pkh to ripemd160(sha256(public_key_compressed.digits))
    bnz_concatenate_ui8(p2pkh, p2pkh, 0, 0); // concatenate 0 byte to msb end of p2pkh.digits
    get_sha256_sha256(&fingerprint, p2pkh, 4); // set fingerprint to first four bytes of sha256(sha256(p2pkh.digits))
    bnz_concatenate_bnz(p2pkh, p2pkh, &fingerprint, 1); // concatenate fingerprint to lsb end of p2pkh
    bnz_trim(p2pkh); // remove zero value bytes from msb end of p2pkh
    bnz_free(&fingerprint); // free fingerprint
}

void get_segwit_p2wpkh_address(bnz_t *p2wpkh, const bnz_t *public_key_compressed)
{
    uint8_t *scriptpubkey_bech32_str = NULL, *witness_program_str = NULL, *p2wpkh_str = NULL, chk_str[7], *bech32_alpha = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    uint32_t i, len, chk = 1;

    bnz_t tmp;
    bnz_init(&tmp);
    get_ripemd160_sha256(&tmp, public_key_compressed, 20); // tmp = ripemd160(sha256(public_key_compressed)), 20 bytes, little endian order
    bnz_reverse_digits(&tmp); // convert tmp.digits to big endian order in preparation for generating the corresponding bech32 format string

    if (!(scriptpubkey_bech32_str = get_base_n_str(&tmp, 32, bech32_alpha, &len))) return; // scriptpubkey_bech32_str = tmp.digits in bech32 format, big endian order
    if (!(witness_program_str = init_uint8_array(45))) return; // prepare uint8_t array for witness_program_str, length = expanded hrp (5) + version (1) + scriptpubkey_bech32_str (32) + zero padding (6) + null terminus (1)
    if (!(p2wpkh_str = init_uint8_array(27))) return; // prepare uint8_t array for numerical part of p2wpkh, length = scriptpubkey_bech32_str (20) + checksum (6) + null terminus (1)
    
    /*

    The witness program comprises four elements: expanded hrp + version + scriptpubkey in bech32 + padding.

    Expanded hrp = "rrqzr", the prefix to witness program.

    Derivation:

    hrp = "bc" = 99 98 in ascii = 01100010 01100011 in binary
    Expanded hrp = 00011 00011 00000 00010 00011, top 3 bits of 'b' and 'c' in ascii padded left to 5 bits + 5 zero bits separator + bottom 5 bits of 'b' and 'c' in ascii
    Numerical values of expanded hrp = 3, 3, 0, 2, 3
    Bech32 encoding of expanded hrp = r, r, q, z, r

    The expanded hrp is followed by a 'q' zero digit representing the segwit version number.

    "qqqqqq" = 6 zero digits in Bech32.

    */

    sprintf(witness_program_str, "rrqzrq00000000000000000000000000000000"); // witness_program_str = "rrqzrq" + 32 zeroes to allow for offset in case strlen(scriptpubkey_bech32_str) < 32
    sprintf(witness_program_str + 38 - strlen(scriptpubkey_bech32_str), "%sqqqqqq", scriptpubkey_bech32_str); // witness_program_str = "rrqzrq" + zero padding if required + scriptpubkey_bech32_str + "qqqqqq"

    //get checksum, occupying 30 bits of uint32_t
    for (i = 0; i < strlen(witness_program_str); i++) {
        chk = segwit_p2wpkh_checksum_update(chk, char_32[witness_program_str[i]]); // dgt = decimal value (0 - 31) corresponding to bech32 character
    }
    chk ^= 1; // finalise checksum, xor with 1 means standard segwit

    // convert checksum from 30 bits formatted as uint32_t (big endian order) into 6 x 5 bit digits in bech32, stored as uint8_t array, little endian order
    for (i = 0; i < 6; i++) {
        chk_str[i] = bech32_alpha[(chk >> ((5 - i) * 5)) & 31];
    }

    sprintf(p2wpkh_str, "%s%s", scriptpubkey_bech32_str, chk_str); // numerical part of address = scriptpubkey_bech32_str (20) + checksum (6)
    bnz_set_str(p2wpkh, p2wpkh_str, 32); // convert p2wpkh_str (numerical part of standard segwit address) into standard bnz_t, will be printed with non-bech32 prefix "bc1q"

    // free resources
    free(scriptpubkey_bech32_str);
    free(witness_program_str);
    free(p2wpkh_str);
    bnz_free(&tmp);
}

uint32_t segwit_p2wpkh_checksum_update(uint32_t chk, uint8_t dgt)
{
    uint8_t top = (chk >> 25); // top = top 5 bits of current chk, formatted as uint8_t
    uint32_t btm = (chk & 33554431) << 5; // btm = bottom 25 bits of current chk (from bitwise AND with 0x1ffffff) padded with 5 zeros at lsb end, formatted as uint32_t
    btm ^= dgt; // xor btm with current digit of witness program, formatted as uint8_t
    if ((top >> 0) & 1) btm ^= 996825010; // if 1st bit of top is set, xor btm with 1st constant (0x3b6a57b2)
    if ((top >> 1) & 1) btm ^= 642813549; // if 2nd bit of top is set, xor btm with 2nd constant (0x26508e6d)
    if ((top >> 2) & 1) btm ^= 513874426; // if 3rd bit of top is set, xor btm with 3rd constant (0x1ea119fa)
    if ((top >> 3) & 1) btm ^= 1027748829; // if 4th bit of top is set, xor btm with 4th constant (0x3d4233dd)
    if ((top >> 4) & 1) btm ^= 705979059; // if 5th bit of top is set, xor btm with 5th constant (0x2a1462b3)
    return btm; // return btm, the new value of chk, formatted as uint32_t
}

void print_segwit_p2wpkh_address(const bnz_t *p2wpkh, const uint8_t *str)
{
    uint8_t *full_string = NULL, *segwit_address_str = NULL;
    uint32_t len;

    /*
    
    Segwit P2WPKH addresses have a prefix "bc1q" which contains non-Bech32 characters
    and is concatenated with the numercial part of the address.
    
    The numerical part is itself a concatenation of the RIPEMD160-SHA256 double
    hash of the compressed public key encoded in Bech32, and a 6 character checksum,
    also formatted in Bech32.

    In bitcoin_math, the numerical part is treated as a number and is stored in
    a standard bnz_t, and the prefix is only added when the Segwit P2WPKH address is
    printed to the screen.

    However, RIPEMD160 digests (and their Bech32 encodings) can have zeroes at the
    msb end, causing issues with printing when the numerical part is treated as a
    number because leading zeroes are not printed.

    bitcoin_math therefore incorporates this dedicated print function for Segwit
    P2WPKH addresses which ensures that, where the numerical part of the address
    has one or more zeroes at the msb end, it is padded with 'q' characters
    (representing zeroes in Bech32) before the prefix is appended. 
    
    */

    bnz_t tmp;
    bnz_init(&tmp);
    bnz_set_bnz(&tmp, p2wpkh); // tmp = local mutable copy of p2wpkh bnz_t with tmp.digits in standard little endian order 
    bnz_reverse_digits(&tmp); // convert tmp.digits to big endian order

    if (!(full_string = init_uint8_array(strlen(str) + 43))) return; // prepare full_string to receive str + 42 characters + null terminator
    if (!(segwit_address_str = get_base_n_str(&tmp, 32, "qpzry9x8gf2tvdw0s3jn54khce6mua7l", &len))) return; // get bech32 string encoding of segwit_address_str in big endian order

    sprintf(full_string, "%sbc1q00000000000000000000000000000000000000", str); // full_string = str + "bc1q" + 38 x '0' + null terminator
    sprintf(full_string + strlen(str) + 42 - len, segwit_address_str); // concatenate Bech32 string with appropriate offset to ensure '0' padding at msb end if required

    printf("%s\n", full_string); // print final string

    bnz_free(&tmp);
}

/* MENU */

uint32_t get_num_input(uint32_t, uint32_t, uint32_t);
void get_str_input(char[], int);
void menu_1_master_keys(const char *);
void menu_2_child_keys(const char *);
void menu_2_1_normal_child(const char *);
void menu_2_2_hardened_child(const char *);
void menu_2_3_public_child(const char *);
void menu_2_4_hdk_intermediate_values(const char *);
void menu_3_base_converter(const char *);
void menu_4_functions(const char *);
void menu_4_1_public_key_to_address(const char *);
void menu_4_2_validate_mnemonic_phrase_checksum(const char *);
void menu_4_3_private_key_to_WIF(const char *);
void menu_4_4_WIF_to_private_key(const char *);
void menu_4_5_secp256k1_point_addition(const char *);
void menu_4_6_secp256k1_point_doubling(const char *);
void menu_4_7_secp256k1_scalar_multiplication(const char *);

uint32_t get_num_input(uint32_t max_len, uint32_t min, uint32_t max) // get base 10 number between min and max from stdin
{
    char str[max_len + 1];
    int i = 0, ch;
    uint32_t res;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (i < max_len && isdigit(ch)) str[i++] = ch;
    }
    str[i] = 0;
    res = strtoul(str, NULL, 10);
    if (res < min || res > max) res = min;
    return res;
}

void get_str_input(char str[], int max_len) // get string from stdin with strlen <= max_len
{
    int i = 0, ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {
        // confine ch to the characters up to base 64 or space
        if (((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '+' || ch == '/' || ch == ' ' || ch == 39 /* apostrophe */ ) && i < max_len) {
            str[i++] = ch;
        }
    }
    str[i] = 0;
}

void menu_1_master_keys(const char *version) // input 256 bits of entropy and generate master private key, master chain code, master public key, and corresponding p2pkh and segwit p2wpkh addresses
{
    uint32_t i, wd_ids[24];
    char entropy_str[257], base = 16, passphrase_str[257], *mnemonic = NULL;
    bnz_t entropy, master_private_key, master_chain_code, xprv, master_public_key, master_public_key_compressed, xpub, seed, p2pkh, p2wpkh;

    PT public_key;

    SECP256K1 secp256k1;

    bnz_init(&entropy);
    bnz_init(&master_private_key);
    bnz_init(&master_chain_code);
    bnz_init(&xprv);
    bnz_init(&master_public_key);
    bnz_init(&master_public_key_compressed);
    bnz_init(&xpub);
    bnz_init(&seed);
    bnz_init(&p2pkh);
    bnz_init(&p2wpkh);
    bnz_init(&public_key.x);
    bnz_init(&public_key.y);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Entropy (press 'Enter' for random): ");
    get_str_input(entropy_str, 256);

    system("cls");
    printf("%s\n\n", version);
    printf("Entropy: ");

    if (isalnum(entropy_str[0])) {
        printf("%s\n", entropy_str);
        printf("Base (2 - 64): ");
        base = get_num_input(2, 0, 64);
        if (base < 2) base = 16;
        bnz_set_str(&entropy, entropy_str, base);
    } else {
        bnz_256_bit_rnd(&entropy);
    }

    system("cls");
    printf("%s\n\n", version); 
    bnz_print(&entropy, 16, "Entropy: ");
    if (base == 16) {
        printf("Base: 16\n");
    } else {
        printf("Base: 16 (converted from base %d)\n", base);
    }

    printf("Passphrase (optional): ");
    get_str_input(passphrase_str, 256);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&entropy, 16, "ENTROPY: ");
    printf("BASE: 16\n");

    if (isalnum(passphrase_str[0])) {
        printf("PASSPHRASE: %s\n\n", passphrase_str);
    } else {
        printf("\n");
    }

    entropy_checksum(&entropy);

    get_bip39_word_ids_bnz(&entropy, wd_ids);

    printf("CHECKSUM: 0x%02x\n\n", entropy.digits[0]);

    printf("BIP39 IDs: %d", wd_ids[0]);
    for (i = 1; i < 24; i++) {
        printf(", %d", wd_ids[i]);
    }
    printf("\n\n");

    mnemonic = get_mnemonic_phrase(wd_ids);
    printf("MNEMONIC PHRASE: %s\n\n", mnemonic);

    get_seed_from_mnemonic_phrase(&seed, mnemonic, passphrase_str);
    bnz_print(&seed, 16, "SEED: ");
    printf("\n");

    get_master_keys(&master_private_key, &master_chain_code, &seed);

    if (bnz_cmp_bnz(&master_private_key, &secp256k1.n) != -1) { // ensure that master_private_key < Secp256k1.n
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&master_private_key, 16, "Master private key: ");
        printf("\n");
        printf("This private key is not less than the order of Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");
        getchar();

        bnz_free(&entropy);
        bnz_free(&master_private_key);
        bnz_free(&master_chain_code);
        bnz_free(&xprv);
        bnz_free(&master_public_key);
        bnz_free(&master_public_key_compressed);
        bnz_free(&xpub);
        bnz_free(&seed);
        bnz_free(&p2pkh);
        bnz_free(&p2wpkh);
        bnz_free(&public_key.x);
        bnz_free(&public_key.y);

        secp256k1_free(secp256k1);

        menu_1_master_keys(version);
    }
    
    get_xprv_master(&xprv, &master_private_key, &master_chain_code);

    bnz_print(&master_private_key, 16, "MASTER PRIVATE KEY: ");
    bnz_print(&master_chain_code, 16, "MASTER CHAIN CODE: ");
    bnz_print(&xprv, 58, "MASTER XPRV: ");

    printf("\nHDK ADDRESSES:\n");
    
    get_wallet_p2pkh_addresses(&master_private_key, &master_chain_code);
    get_wallet_p2wpkh_addresses(&master_private_key, &master_chain_code);

    bnz_free(&entropy);
    bnz_free(&master_private_key);
    bnz_free(&master_chain_code);
    bnz_free(&xprv);
    bnz_free(&master_public_key);
    bnz_free(&master_public_key_compressed);
    bnz_free(&xpub);
    bnz_free(&seed);
    bnz_free(&p2pkh);
    bnz_free(&p2wpkh);
    bnz_free(&public_key.x);
    bnz_free(&public_key.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_2_child_keys(const char *version)
{
    int menu;
    system("cls");
    printf("%s\n\n", version);
    printf("1. Normal child\n");
    printf("2. Hardened child\n");
    printf("3. Child public key\n");
    printf("4. HDK intermediate values\n");
    printf("\n");
    menu = get_num_input(1, 0, 4);
    switch (menu) {
        case 1:
            menu_2_1_normal_child(version);
            break;
        case 2:
            menu_2_2_hardened_child(version);
            break;
        case 3:
            menu_2_3_public_child(version);
            break;
        case 4:
            menu_2_4_hdk_intermediate_values(version);
            break;
        default:
            break;
    }
}

void menu_2_1_normal_child(const char *version)
{
    uint8_t parent_private_key_str[67], parent_chain_code_str[67], index_str[11], mac[65], depth_num;
    uint32_t index_num;
    bnz_t tmp, index, entropy, parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, xprv, child_public_key_compressed, xpub, p2pkh, p2wpkh;
    PT parent_public_key_pt, child_public_key_pt;
    SECP256K1 secp256k1;

    secp256k1 = secp256k1_init();

    bnz_init(&tmp);
    bnz_init(&index);
    bnz_init(&entropy);
    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&xprv);
    bnz_init(&child_public_key_compressed);
    bnz_init(&xpub);
    bnz_init(&p2pkh);
    bnz_init(&p2wpkh);

    bnz_init(&parent_public_key_pt.x);
    bnz_init(&parent_public_key_pt.y);
    bnz_init(&child_public_key_pt.x);
    bnz_init(&child_public_key_pt.y);

    system("cls");
    printf("%s\n\n", version);

    printf("Parent private key (press 'Enter' for random): ");
    get_str_input(parent_private_key_str, 66);

    if (isalnum(parent_private_key_str[0])) {
        printf("%s\n", parent_private_key_str);
        bnz_set_str(&parent_private_key, parent_private_key_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        printf("Parent chain code: ");
        get_str_input(parent_chain_code_str, 66);
        bnz_set_str(&parent_chain_code, parent_chain_code_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    } else {
        get_random_master_keys(&entropy, &parent_private_key, &parent_chain_code);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&entropy, 16, "Entropy: ");
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    }

    if (bnz_cmp_bnz(&parent_private_key, &secp256k1.n) != -1) { // ensure that parent_private_key < Secp256k1.n
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        printf("\n");
        printf("This private key is not less than the order of Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");
        getchar();

        bnz_free(&tmp);
        bnz_free(&index);
        bnz_free(&entropy);
        bnz_free(&parent_private_key);
        bnz_free(&parent_chain_code);
        bnz_free(&parent_public_key_compressed);
        bnz_free(&child_private_key);
        bnz_free(&child_chain_code);
        bnz_free(&xprv);
        bnz_free(&child_public_key_compressed);
        bnz_free(&xpub);
        bnz_free(&p2pkh);
        bnz_free(&p2wpkh);

        bnz_free(&parent_public_key_pt.x);
        bnz_free(&parent_public_key_pt.y);
        bnz_free(&child_public_key_pt.x);
        bnz_free(&child_public_key_pt.y);

        secp256k1_free(secp256k1);

        menu_2_1_normal_child(version);
    }

    printf("\n");
    printf("Depth (1 to 255): ");
    depth_num = get_num_input(3, 1, 255);

    system("cls");
    printf("%s\n\n", version);
    if (!bnz_is_zero(&entropy)) bnz_print(&entropy, 16, "Entropy: ");
    bnz_print(&parent_private_key, 16, "Parent private key: ");
    bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    printf("\n");
    printf("Depth: %u\n", depth_num);
    printf("Index (0 to 2147483647): ");
    index_num = get_num_input(11, 0, 2147483647);

    get_public_key(&parent_public_key_pt, &parent_public_key_compressed, &parent_private_key);

    system("cls");
    printf("%s\n\n", version);
    if (!bnz_is_zero(&entropy)) bnz_print(&entropy, 16, "ENTROPY: ");
    bnz_print(&parent_private_key, 16, "PARENT PRIVATE KEY: ");
    bnz_print(&parent_chain_code, 16, "PARENT CHAIN CODE: ");
    bnz_print(&parent_public_key_compressed, 16, "PARENT PUBLIC KEY COMPRESSED: ");
    bnz_print(&parent_public_key_pt.x, 16, " x: ");
    bnz_print(&parent_public_key_pt.y, 16, " y: ");
    printf("\n");
    printf("DEPTH: %u\n", depth_num);
    printf("INDEX: %u\n", index_num);
    printf("\n");

    get_child_normal(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, &parent_public_key_compressed, index_num);
    get_xprv_child(&xprv, depth_num, index_num, &parent_public_key_compressed, &child_private_key, &child_chain_code); // serialise xprv

    bnz_print(&child_private_key, 16, "CHILD PRIVATE KEY: ");
    bnz_print(&child_chain_code, 16, "CHILD CHAIN CODE: ");
    bnz_print(&xprv, 58, "CHILD XPRV: ");
    printf("\n");

    get_public_key(&child_public_key_pt, &child_public_key_compressed, &child_private_key); // generate compressed public key from private key
    get_xpub_child(&xpub, depth_num, index_num, &parent_public_key_compressed, &child_public_key_compressed, &child_chain_code); // serialise xpub
    get_p2pkh_address(&p2pkh, &child_public_key_compressed); // serialise p2pkh address
    get_segwit_p2wpkh_address(&p2wpkh, &parent_public_key_compressed); // serialise segwit address

    bnz_print(&child_public_key_compressed, 16, "CHILD PUBLIC KEY COMPRESSED: ");
    bnz_print(&child_public_key_pt.x, 16, " x: ");
    bnz_print(&child_public_key_pt.y, 16, " y: ");
    bnz_print(&xpub, 58, "CHILD XPUB: ");
    bnz_print(&p2pkh, 58, "CHILD P2PKH ADDRESS: 1"); // need to print 1 before the P2PKH address because it corresponds to a leading zero at the msb end when treated as a number
    print_segwit_p2wpkh_address(&p2wpkh, "CHILD SEGWIT P2WPKH ADDRESS: ");
    printf("\n");

    bnz_free(&tmp);
    bnz_free(&index);
    bnz_free(&entropy);
    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&xprv);
    bnz_free(&child_public_key_compressed);
    bnz_free(&xpub);
    bnz_free(&p2pkh);
    bnz_free(&p2wpkh);

    bnz_free(&parent_public_key_pt.x);
    bnz_free(&parent_public_key_pt.y);
    bnz_free(&child_public_key_pt.x);
    bnz_free(&child_public_key_pt.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_2_2_hardened_child(const char *version)
{
    uint8_t parent_private_key_str[67], parent_chain_code_str[67], index_str[11], mac[65], depth_num;
    uint32_t index_num;
    bnz_t tmp, index, entropy, parent_private_key, parent_chain_code, parent_public_key_compressed, child_private_key, child_chain_code, xprv, child_public_key_compressed, xpub, p2pkh, p2wpkh;
    PT parent_public_key_pt, child_public_key_pt;
    SECP256K1 secp256k1;

    secp256k1 = secp256k1_init();

    bnz_init(&tmp);
    bnz_init(&index);
    bnz_init(&entropy);
    bnz_init(&parent_private_key);
    bnz_init(&parent_chain_code);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&child_private_key);
    bnz_init(&child_chain_code);
    bnz_init(&xprv);
    bnz_init(&child_public_key_compressed);
    bnz_init(&xpub);
    bnz_init(&p2pkh);
    bnz_init(&p2wpkh);

    bnz_init(&parent_public_key_pt.x);
    bnz_init(&parent_public_key_pt.y);
    bnz_init(&child_public_key_pt.x);
    bnz_init(&child_public_key_pt.y);

    system("cls");
    printf("%s\n\n", version);

    printf("Parent private key (press 'Enter' for random): ");
    get_str_input(parent_private_key_str, 66);

    if (isalnum(parent_private_key_str[0])) {
        printf("%s\n", parent_private_key_str);
        bnz_set_str(&parent_private_key, parent_private_key_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        printf("Parent chain code: ");
        get_str_input(parent_chain_code_str, 66);
        bnz_set_str(&parent_chain_code, parent_chain_code_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    } else {
        get_random_master_keys(&entropy, &parent_private_key, &parent_chain_code);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&entropy, 16, "Entropy: ");
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    }

    if (bnz_cmp_bnz(&parent_private_key, &secp256k1.n) != -1) { // ensure that parent_private_key < Secp256k1.n
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_private_key, 16, "Parent private key: ");
        printf("\n");
        printf("This private key is not less than the order of Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");

        getchar();

        bnz_free(&tmp);
        bnz_free(&index);
        bnz_free(&entropy);
        bnz_free(&parent_private_key);
        bnz_free(&parent_chain_code);
        bnz_free(&parent_public_key_compressed);
        bnz_free(&child_private_key);
        bnz_free(&child_chain_code);
        bnz_free(&xprv);
        bnz_free(&child_public_key_compressed);
        bnz_free(&xpub);
        bnz_free(&p2pkh);
        bnz_free(&p2wpkh);
    
        secp256k1_free(secp256k1);

        menu_2_2_hardened_child(version);
    }

    printf("\n");
    printf("Depth (1 to 255): ");
    depth_num = get_num_input(3, 1, 255);

    system("cls");
    printf("%s\n\n", version);
    if (!bnz_is_zero(&entropy)) bnz_print(&entropy, 16, "Entropy: ");
    bnz_print(&parent_private_key, 16, "Parent private key: ");
    bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    printf("\n");
    printf("Depth: %u\n", depth_num);
    printf("Index (2147483648 to 4294967295): ");
    index_num = get_num_input(10, 0, 4294967295);
    if (index_num < 2147483648) index_num += 2147483648;

    get_public_key(&parent_public_key_pt, &parent_public_key_compressed, &parent_private_key);

    system("cls");
    printf("%s\n\n", version);
    if (!bnz_is_zero(&entropy)) bnz_print(&entropy, 16, "ENTROPY: ");
    bnz_print(&parent_private_key, 16, "PARENT PRIVATE KEY: ");
    bnz_print(&parent_chain_code, 16, "PARENT CHAIN CODE: ");
    bnz_print(&parent_public_key_compressed, 16, "PARENT PUBLIC KEY COMPRESSED: ");
    bnz_print(&parent_public_key_pt.x, 16, " x: ");
    bnz_print(&parent_public_key_pt.y, 16, " y: ");
    printf("\n");
    printf("DEPTH: %u\n", depth_num);
    printf("INDEX: %u\n", index_num);
    printf("\n");

    get_child_hardened(&child_private_key, &child_chain_code, &parent_private_key, &parent_chain_code, index_num);
    get_xprv_child(&xprv, depth_num, index_num, &parent_public_key_compressed, &child_private_key, &child_chain_code); // serialise xprv

    bnz_print(&child_private_key, 16, "CHILD PRIVATE KEY: ");
    bnz_print(&child_chain_code, 16, "CHILD CHAIN CODE: ");
    bnz_print(&xprv, 58, "CHILD XPRV: ");
    printf("\n");

    get_public_key(&child_public_key_pt, &child_public_key_compressed, &child_private_key); // generate compressed public key from private key
    get_xpub_child(&xpub, depth_num, index_num, &parent_public_key_compressed, &child_public_key_compressed, &child_chain_code); // serialise xpub
    get_p2pkh_address(&p2pkh, &child_public_key_compressed); // serialise p2pkh address
    get_segwit_p2wpkh_address(&p2wpkh, &child_public_key_compressed);

    bnz_print(&child_public_key_compressed, 16, "CHILD PUBLIC KEY COMPRESSED: ");
    bnz_print(&child_public_key_pt.x, 16, " x: ");
    bnz_print(&child_public_key_pt.y, 16, " y: ");
    bnz_print(&xpub, 58, "CHILD XPUB: ");
    bnz_print(&p2pkh, 58, "CHILD P2PKH ADDRESS: 1"); // need to print 1 before the P2PKH address because it corresponds to a leading zero at the msb end when treated as a number
    print_segwit_p2wpkh_address(&p2wpkh, "CHILD SEGWIT P2WPKH ADDRESS: ");
    printf("\n");

    bnz_free(&tmp);
    bnz_free(&index);
    bnz_free(&entropy);
    bnz_free(&parent_private_key);
    bnz_free(&parent_chain_code);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&child_private_key);
    bnz_free(&child_chain_code);
    bnz_free(&xprv);
    bnz_free(&child_public_key_compressed);
    bnz_free(&xpub);
    bnz_free(&p2pkh);
    bnz_free(&p2wpkh);

    bnz_free(&child_public_key_pt.x);
    bnz_free(&child_public_key_pt.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_2_3_public_child(const char *version)
{
    uint8_t parent_public_key_compressed_str[69], parent_chain_code_str[67], index_str[11], mac[65], depth_num;
    uint32_t index_num;
    bnz_t tmp, index, parent_public_key_compressed, parent_chain_code, child_public_key_compressed, child_chain_code, xpub, p2pkh, p2wpkh;
    PT tmp_key, parent_public_key_pt, child_public_key_pt;

    SECP256K1 secp256k1;

    bnz_init(&tmp);
    bnz_init(&index);
    bnz_init(&parent_public_key_compressed);
    bnz_init(&parent_chain_code);
    bnz_init(&child_public_key_compressed);
    bnz_init(&child_chain_code);
    bnz_init(&xpub);
    bnz_init(&p2pkh);
    bnz_init(&p2wpkh);

    bnz_init(&tmp_key.x);
    bnz_init(&tmp_key.y);
    bnz_init(&parent_public_key_pt.x);
    bnz_init(&parent_public_key_pt.y);
    bnz_init(&child_public_key_pt.x);
    bnz_init(&child_public_key_pt.y);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Parent public key compressed: ");
    get_str_input(parent_public_key_compressed_str, 68); // optional "0x" + 33 bytes

    if (isalnum(parent_public_key_compressed_str[0])) {
        printf("%s\n", parent_public_key_compressed_str);
        bnz_set_str(&parent_public_key_compressed, parent_public_key_compressed_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_public_key_compressed, 16, "Parent public key compressed: ");
        printf("Parent chain code: ");
        get_str_input(parent_chain_code_str, 66); // 32 bytes + optional "0x"
        bnz_set_str(&parent_chain_code, parent_chain_code_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&parent_public_key_compressed, 16, "Parent public key compressed: ");
        bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    } else {
        return;
    }

    printf("\n");
    printf("Depth (1 to 255): ");
    depth_num = get_num_input(3, 1, 255);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&parent_public_key_compressed, 16, "Parent public key compressed: ");
    bnz_print(&parent_chain_code, 16, "Parent chain code: ");
    printf("\n");
    printf("Depth: %u\n", depth_num);
    printf("Index (0 to 2147483647): ");
    index_num = get_num_input(10, 0, 2147483647);

    get_public_key_xy(&parent_public_key_pt, &parent_public_key_compressed);

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&parent_chain_code, 16, "PARENT CHAIN CODE: ");
    bnz_print(&parent_public_key_compressed, 16, "PARENT PUBLIC KEY COMPRESSED: ");
    bnz_print(&parent_public_key_pt.x, 16, " x: ");
    bnz_print(&parent_public_key_pt.y, 16, " y: ");
    printf("\n");
    printf("DEPTH: %u\n", depth_num);
    printf("INDEX: %u\n", index_num);
    printf("\n");

    bnz_set_i32(&index, index_num); // convert index to bnz_t
    bnz_resize(&index, 4, 1); // ensure that index is four bytes
    bnz_resize(&parent_public_key_compressed, 33, 1); // ensure that parent_public_key_compressed is 33 bytes
    bnz_resize(&parent_chain_code, 32, 1); // ensure that parent_chain_code is 32 bytes

    bnz_concatenate_bnz(&tmp, &parent_public_key_compressed, &index, 1); // tmp = parent_public_key_compressed concatenated with index

    bnz_reverse_digits(&tmp);  // convert tmp.digits to big endian in preparation for hmac_512
    bnz_reverse_digits(&parent_chain_code); // convert parent_chain_code.digits to big endian in preparation for hmac_512

    hmac_sha512(parent_chain_code.digits, parent_chain_code.size, tmp.digits, tmp.size, mac, 64); // generate mac
    bnz_reverse_digits(&parent_chain_code); // convert parent_chain_code.digits back to default little endian

    bnz_resize(&tmp, 32, 0); // resize and zero tmp in preparation for receipt of first 32 bytes of mac
    memcpy(tmp.digits, mac, 32); // copy first 32 bytes of mac into tmp.digits
    bnz_reverse_digits(&tmp); // convert tmp.digits back to default little endian

    secp256k1_scalar_multiplication(secp256k1, &tmp, &tmp_key); // tmp = (secp256k1.G * tmp) mod secp256k1.p, a point on secp256k1
    secp256k1_point_addition(secp256k1, &parent_public_key_pt, &tmp_key, &child_public_key_pt); // child_public_key_pt = (parent_public_key_pt + tmp) mod secp256k1.p

    if (bnz_bit_set(&child_public_key_pt.y, 0) == 0) { // even
        bnz_concatenate_ui8(&child_public_key_compressed, &child_public_key_pt.x, 2, 0); // prepend 2
    } else { // odd
        bnz_concatenate_ui8(&child_public_key_compressed, &child_public_key_pt.x, 3, 0); // prepend 3
    }

    bnz_resize(&child_chain_code, 32, 0); // resize and zero child_chain_code in preparation for receipt of last 32 bytes of mac
    memcpy(child_chain_code.digits, mac + 32, 32); // copy first 32 bytes of mac into child_chain_code.digits
    bnz_reverse_digits(&child_chain_code); // convert child_chain_code.digits back to default little endian

    get_xpub_child(&xpub, depth_num, index_num, &parent_public_key_compressed, &child_public_key_compressed, &child_chain_code); // serialise xpub
    get_p2pkh_address(&p2pkh, &child_public_key_compressed); // serialise p2pkh address
    get_segwit_p2wpkh_address(&p2wpkh, &child_public_key_compressed);

    bnz_print(&child_chain_code, 16, "CHILD CHAIN CODE: ");
    bnz_print(&child_public_key_compressed, 16, "CHILD PUBLIC KEY COMPRESSED: ");
    bnz_print(&child_public_key_pt.x, 16, " x: ");
    bnz_print(&child_public_key_pt.y, 16, " y: ");
    bnz_print(&xpub, 58, "CHILD XPUB: ");
    bnz_print(&p2pkh, 58, "CHILD P2PKH ADDRESS: 1"); // need to print 1 before the P2PKH address because it corresponds to a leading zero at the msb end when treated as a number
    print_segwit_p2wpkh_address(&p2wpkh, "CHILD SEGWIT P2WPKH ADDRESS: ");
    printf("\n");

    bnz_free(&tmp);
    bnz_free(&index);
    bnz_free(&parent_public_key_compressed);
    bnz_free(&parent_chain_code);
    bnz_free(&child_public_key_compressed);
    bnz_free(&child_chain_code);
    bnz_free(&xpub);
    bnz_free(&p2pkh);
    bnz_free(&p2wpkh);

    bnz_free(&tmp_key.x);
    bnz_free(&tmp_key.y);
    bnz_free(&parent_public_key_pt.x);
    bnz_free(&parent_public_key_pt.y);
    bnz_free(&child_public_key_pt.x);
    bnz_free(&child_public_key_pt.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_2_4_hdk_intermediate_values(const char *version)
{
    char hdk_str[32], master_private_key_str[67], master_chain_code_str[67];

    bnz_t entropy, master_private_key, master_chain_code;

    SECP256K1 secp256k1;

    bnz_init(&entropy);
    bnz_init(&master_private_key);
    bnz_init(&master_chain_code);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Master private key (press 'Enter' for random): ");
    get_str_input(master_private_key_str, 66);

    if (isalnum(master_private_key_str[0])) {
        printf("%s\n", master_private_key_str);
        bnz_set_str(&master_private_key, master_private_key_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&master_private_key, 16, "Master private key: ");
        printf("Master chain code: ");
        get_str_input(master_chain_code_str, 66);
        bnz_set_str(&master_chain_code, master_chain_code_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&master_private_key, 16, "Master private key: ");
        bnz_print(&master_chain_code, 16, "Master chain code: ");
    } else {
        get_random_master_keys(&entropy, &master_private_key, &master_chain_code);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&entropy, 16, "Entropy: ");
        bnz_print(&master_private_key, 16, "Master private key: ");
        bnz_print(&master_chain_code, 16, "Master chain code: ");
    }

    if (bnz_cmp_bnz(&master_private_key, &secp256k1.n) != -1) { // ensure that master_private_key < Secp256k1.n
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&master_private_key, 16, "Master private key: ");
        printf("\n");
        printf("This private key is not less than the order of Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");

        getchar();

        bnz_free(&entropy);
        bnz_free(&master_private_key);
        bnz_free(&master_chain_code);
    
        secp256k1_free(secp256k1);

        menu_2_4_hdk_intermediate_values(version);
    }

    printf("\n");
    printf("HDK string (e.g. m/44'/0'/0'/0/0): ");
    get_str_input(hdk_str, 31);

    system("cls");
    printf("%s\n\n", version);
    if (!bnz_is_zero(&entropy)) bnz_print(&entropy, 16, "ENTROPY: ");
    bnz_print(&master_private_key, 16, "MASTER PRIVATE KEY: ");
    bnz_print(&master_chain_code, 16, "MASTER CHAIN CODE: ");
    printf("HDK STRING: %s\n", hdk_str);
    printf("\n");

    get_hdk_intermediate_values(&master_private_key, &master_chain_code, hdk_str);

    bnz_free(&entropy);
    bnz_free(&master_private_key);
    bnz_free(&master_chain_code);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_3_base_converter(const char *version)
{
    char number_str[2049], base = 16;
    bnz_t number;

    bnz_init(&number);

    system("cls");
    printf("%s\n\n", version);

    printf("Number (press 'Enter' for random): ");
    get_str_input(number_str, 2048);

    system("cls");
    printf("%s\n\n", version);

    if (isalnum(number_str[0])) {
        printf("Number: %s\n", number_str);
        printf("Base (2 - 64): ");
        base = get_num_input(3, 2, 64);
        if (base == 0) base = 16;
        bnz_set_str(&number, number_str, base);
    } else {
        bnz_256_bit_rnd(&number);
    }

    system("cls");
    printf("%s\n\n", version);
    bnz_print(&number, base, "Number: ");
    printf("Base: %d\n\n", base);

    bnz_print(&number, -2, "Binary: ");
    printf("\n");

    bnz_print(&number, 8, "Octal: ");
    printf("\n");

    bnz_print(&number, 10, "Decimal: ");
    printf("\n");

    bnz_print(&number, 16, "Hex: ");
    printf("\n");

    bnz_print(&number, 32, "Bech32: ");
    printf("\n");

    bnz_print(&number, 58, "Bitcoin base 58: ");
    printf("\n");

    bnz_print(&number, 256, "Bytes: ");
    printf("\n");

    bnz_print(&number, 2, "Base 2: ");
    bnz_print(&number, 3, "Base 3: ");
    bnz_print(&number, 4, "Base 4: ");
    bnz_print(&number, 5, "Base 5: ");
    bnz_print(&number, 6, "Base 6: ");
    bnz_print(&number, 7, "Base 7: ");
    bnz_print(&number, 8, "Base 8: ");
    bnz_print(&number, 9, "Base 9: ");

    printf("\n");

    bnz_print(&number, 10, "Base 10: ");
    bnz_print(&number, 11, "Base 11: ");
    bnz_print(&number, 12, "Base 12: ");
    bnz_print(&number, 13, "Base 13: ");
    bnz_print(&number, 14, "Base 14: ");
    bnz_print(&number, 15, "Base 15: ");
    bnz_print(&number, -16, "Base 16: ");
    bnz_print(&number, 17, "Base 17: ");
    bnz_print(&number, 18, "Base 18: ");
    bnz_print(&number, 19, "Base 19: ");

    printf("\n");

    bnz_print(&number, 20, "Base 20: ");
    bnz_print(&number, 21, "Base 21: ");
    bnz_print(&number, 22, "Base 22: ");
    bnz_print(&number, 23, "Base 23: ");
    bnz_print(&number, 24, "Base 24: ");
    bnz_print(&number, 25, "Base 25: ");
    bnz_print(&number, 26, "Base 26: ");
    bnz_print(&number, 27, "Base 27: ");
    bnz_print(&number, 28, "Base 28: ");
    bnz_print(&number, 29, "Base 29: ");

    printf("\n");

    bnz_print(&number, 30, "Base 30: ");
    bnz_print(&number, 31, "Base 31: ");
    bnz_print(&number, -32, "Base 32: ");
    bnz_print(&number, 33, "Base 33: ");
    bnz_print(&number, 34, "Base 34: ");
    bnz_print(&number, 35, "Base 35: ");
    bnz_print(&number, 36, "Base 36: ");
    bnz_print(&number, 37, "Base 37: ");
    bnz_print(&number, 38, "Base 38: ");
    bnz_print(&number, 39, "Base 39: ");

    printf("\n");

    bnz_print(&number, 40, "Base 40: ");
    bnz_print(&number, 41, "Base 41: ");
    bnz_print(&number, 42, "Base 42: ");
    bnz_print(&number, 43, "Base 43: ");
    bnz_print(&number, 44, "Base 44: ");
    bnz_print(&number, 45, "Base 45: ");
    bnz_print(&number, 46, "Base 46: ");
    bnz_print(&number, 47, "Base 47: ");
    bnz_print(&number, 48, "Base 48: ");
    bnz_print(&number, 49, "Base 49: ");

    printf("\n");

    bnz_print(&number, 50, "Base 50: ");
    bnz_print(&number, 51, "Base 51: ");
    bnz_print(&number, 52, "Base 52: ");
    bnz_print(&number, 53, "Base 53: ");
    bnz_print(&number, 54, "Base 54: ");
    bnz_print(&number, 55, "Base 55: ");
    bnz_print(&number, 56, "Base 56: ");
    bnz_print(&number, 57, "Base 57: ");
    bnz_print(&number, -58, "Base 58: ");
    bnz_print(&number, 59, "Base 59: ");

    printf("\n");

    bnz_print(&number, 60, "Base 60: ");
    bnz_print(&number, 61, "Base 61: ");
    bnz_print(&number, 62, "Base 62: ");
    bnz_print(&number, 63, "Base 63: ");
    bnz_print(&number, 64, "Base 64: ");

    printf("\n");

    bnz_free(&number);

    printf("press any key to continue...");

    getchar();
}

void menu_4_functions(const char *version)
{
    int menu;
    system("cls");
    printf("%s\n\n", version);
    printf("1. Public key to P2PKH and P2WPKH\n");
    printf("2. Validate mnemonic phrase checksum\n");
    printf("3. Private key to WIF / public key / P2PKH / P2WPKH address\n");
    printf("4. WIF to private key / public key / P2PKH / P2WPKH address\n");
    printf("5. Secp256k1 point addition\n");
    printf("6. Secp256k1 point doubling\n");
    printf("7. Secp256k1 scalar multiplication\n");
    printf("\n");
    menu = get_num_input(1, 0, 7);
    switch (menu) {
        case 1:
            menu_4_1_public_key_to_address(version);
            break;
        case 2:
            menu_4_2_validate_mnemonic_phrase_checksum(version);
            break;
        case 3:
            menu_4_3_private_key_to_WIF(version);
            break;
        case 4:
            menu_4_4_WIF_to_private_key(version);
            break;
        case 5:
            menu_4_5_secp256k1_point_addition(version);
            break;
        case 6:
            menu_4_6_secp256k1_point_doubling(version);
            break;
        case 7:
            menu_4_7_secp256k1_scalar_multiplication(version);
            break;
        default:
            break;
    }
}

void menu_4_1_public_key_to_address(const char *version)
{
    uint8_t public_key_compressed_str[69]; // optional "0x" + 33 bytes + null terminus
    bnz_t public_key_compressed, p2pkh, p2wpkh;

    bnz_init(&public_key_compressed);
    bnz_init(&p2pkh);
    bnz_init(&p2wpkh);

    system("cls");
    printf("%s\n\n", version);

    printf("Public key (compressed): ");
    get_str_input(public_key_compressed_str, 68);
    bnz_set_str(&public_key_compressed, public_key_compressed_str, 16);

    system("cls");
    printf("%s\n\n", version);

    bnz_print(&public_key_compressed, 16, "PUBLIC KEY (COMPRESSED): ");
    printf("\n");

    get_p2pkh_address(&p2pkh, &public_key_compressed);
    get_segwit_p2wpkh_address(&p2wpkh, &public_key_compressed);

    bnz_print(&p2pkh, 58, "P2PKH ADDRESS: 1"); // need to print 1 before the P2PKH address because it corresponds to a leading zero at the msb end when treated as a number
    printf("\n");

    print_segwit_p2wpkh_address(&p2wpkh, "SEGWIT P2WPKH ADDRESS: ");
    printf("\n");

    bnz_free(&public_key_compressed);
    bnz_free(&p2pkh);
    bnz_free(&p2wpkh);

    printf("press any key to continue...");

    getchar();
}

void menu_4_2_validate_mnemonic_phrase_checksum(const char *version) // check validity of entropy checksum from mnemonic phrase comprising 24 BIP39 words
{
    uint8_t chk;
    int i;
    uint32_t wd_ids[24];
    char mnemonic_str[257], base = 16, passphrase_str[257];
    bnz_t entropy, entropy_chk;

    bnz_init(&entropy);
    bnz_init(&entropy_chk);

    system("cls");
    printf("%s\n\n", version);

    printf("Mnemonic phrase (24 BIP39 words): ");
    get_str_input(mnemonic_str, 256);

    system("cls");
    printf("%s\n\n", version);
    printf("Mnemonic phrase: ");

    if (isalnum(mnemonic_str[0])) {
        printf("%s\n", mnemonic_str);
    } else {
        return;
    }

    system("cls");
    printf("%s\n\n", version);
    printf("MNEMONIC PHRASE: ");

    printf("%s\n\n", mnemonic_str);

    get_bip39_word_ids_str(&entropy_chk, &entropy, &chk, mnemonic_str);

    bnz_print(&entropy, 16, "ENTROPY (HEX): ");
    printf("\n");
    bnz_print(&entropy, 2, "ENTROPY (BINARY): ");
    printf("\n");
    if (chk == entropy_chk.digits[0]) {
        printf("CHECKSUM OK: %#02x\n\n", chk);
    } else {
        printf("CHECKSUM ERROR: %#02x SHOULD BE %#02x\n\n", chk, entropy_chk.digits[0]);
    }

    bnz_free(&entropy);
    bnz_free(&entropy_chk);

    printf("press any key to continue...");

    getchar();
}

void menu_4_3_private_key_to_WIF(const char *version)
{
    uint8_t private_key_str[67]; // optional "0x" + 32 bytes + null terminus
    bnz_t private_key_wif, private_key, entropy, chain_code, public_key_compressed, p2pkh, p2wpkh, fingerprint;
    PT public_key;
    
    SECP256K1 secp256k1;

    bnz_init(&private_key_wif);
    bnz_init(&private_key);
    bnz_init(&entropy);
    bnz_init(&chain_code);
    bnz_init(&public_key_compressed);
    bnz_init(&p2pkh);
    bnz_init(&p2wpkh);
    bnz_init(&public_key.x);
    bnz_init(&public_key.y);
    bnz_init(&fingerprint);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Private key (press 'Enter' for random): ");
    get_str_input(private_key_str, 66);

    if (isalnum(private_key_str[0])) {
        printf("%s\n", private_key_str);
        bnz_set_str(&private_key, private_key_str, 16);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&private_key, 16, "Private key: ");
    } else {
        get_random_master_keys(&entropy, &private_key, &chain_code);
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&entropy, 16, "Entropy: ");
        bnz_print(&private_key, 16, "Private key: ");
    }

    printf("\n");

    if (bnz_cmp_bnz(&private_key, &secp256k1.n) != -1) { // ensure that private_key < Secp256k1.n
        system("cls");
        printf("%s\n\n", version);
        bnz_print(&private_key, 16, "Private key: ");
        printf("\n");
        printf("This private key is not less than the order of Secp256k1.\n\n");
        printf("It is not possible to generate a public key from this private key.\n\n");
        printf("Press any key to rerun the command with a different private key value.\n");

        getchar();

        bnz_free(&private_key_wif);
        bnz_free(&private_key);
        bnz_free(&entropy);
        bnz_free(&chain_code);
        bnz_free(&public_key_compressed);
        bnz_free(&p2pkh);
        bnz_free(&public_key.x);
        bnz_free(&public_key.y);
        bnz_free(&fingerprint);
    
        secp256k1_free(secp256k1);

        menu_4_3_private_key_to_WIF(version);
    }

    bnz_set_bnz(&private_key_wif, &private_key); // copy private key to private_key_wif
    bnz_concatenate_ui8(&private_key_wif, &private_key_wif, 0x80, 0); // mainnet version, concatenate 0x80 to msb end (for testnet version concatenate 0xef)
    bnz_concatenate_ui8(&private_key_wif, &private_key_wif, 0x01, 1); // compressed, concatenate 0x01 to lsb end (no concatenatation for uncompressed)

    get_sha256_sha256(&fingerprint, &private_key_wif, 4); // set fingerprint to first four bytes of sha256(sha256(private_key_wif.digits))
    bnz_concatenate_bnz(&private_key_wif, &private_key_wif, &fingerprint, 1); // concatenate fingerprint to lsb end of private_key_wif

    system("cls");
    printf("%s\n\n", version);

    if (!bnz_is_zero(&entropy)) bnz_print(&entropy, 16, "ENTROPY: ");
    bnz_print(&private_key, 16, "PRIVATE KEY: ");
    bnz_print(&private_key_wif, 16, "PRIVATE KEY WIF (HEX): "); // hex version of WIF
    bnz_print(&private_key_wif, 58, "PRIVATE KEY WIF (BITCOIN BASE 58): "); // Bitcoin Base 58 version of WIF (standard)

    get_public_key(&public_key, &public_key_compressed, &private_key);
    get_p2pkh_address(&p2pkh, &public_key_compressed);
    get_segwit_p2wpkh_address(&p2wpkh, &public_key_compressed);

    printf("\n");

    bnz_print(&public_key_compressed, 16, "PUBLIC KEY (COMPRESSED): ");
    bnz_print(&p2pkh, 58, "P2PKH ADDRESS: 1"); // need to print 1 before the P2PKH address because it corresponds to a leading zero at the msb end when treated as a number
    print_segwit_p2wpkh_address(&p2wpkh, "SEGWIT P2WPKH ADDRESS: ");

    printf("\n");

    bnz_free(&private_key_wif);
    bnz_free(&private_key);
    bnz_free(&entropy);
    bnz_free(&chain_code);
    bnz_free(&public_key_compressed);
    bnz_free(&p2pkh);
    bnz_free(&public_key.x);
    bnz_free(&public_key.y);
    bnz_free(&fingerprint);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_4_4_WIF_to_private_key(const char *version)
{
    uint8_t wif_str[53]; // 51 or 52 Bitcoin base 58 characters + null terminus
    bnz_t private_key_wif, private_key, public_key_compressed, p2pkh, p2wpkh;

    PT public_key;

    SECP256K1 secp256k1;
    
    bnz_init(&private_key_wif);
    bnz_init(&private_key);
    bnz_init(&public_key_compressed);
    bnz_init(&p2pkh);
    bnz_init(&p2wpkh);
    bnz_init(&public_key.x);
    bnz_init(&public_key.y);

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Private key WIF (Bitcoin base 58): ");
    get_str_input(wif_str, 52);

    printf("%s\n", wif_str);
    bnz_set_str(&private_key_wif, wif_str, 58);
    system("cls");
    printf("%s\n\n", version);
    bnz_print(&private_key_wif, 58, "Private key WIF (Bitcoin base 58): ");

    printf("\n");

    bnz_set_bnz(&private_key, &private_key_wif); // copy wif to private key
    bnz_resize(&private_key, private_key.size - 1, 1); // remove version byte from msb end
    bnz_reverse_digits(&private_key); // reverse private_key.digits to enable 4 checksum bytes to be removed from msb end
    bnz_resize(&private_key, private_key.size - 4, 1); // remove 4 checksum bytes from msb end
    bnz_resize(&private_key, 32, 1); // resize private_key.digits to 32 bytes to ensure than the compression byte (if present) is deleted
    bnz_reverse_digits(&private_key); // reverse private_key.digits to standard little endian order

    system("cls");
    printf("%s\n\n", version);

    bnz_print(&private_key_wif, 58, "PRIVATE KEY WIF (BITCOIN BASE 58): "); // Bitcoin Base 58 version of WIF (standard)
    bnz_print(&private_key_wif, 16, "PRIVATE KEY WIF (HEX): "); // hex version of WIF
    bnz_print(&private_key, 16, "PRIVATE KEY: "); // hex version of private key

    get_public_key(&public_key, &public_key_compressed, &private_key);
    get_p2pkh_address(&p2pkh, &public_key_compressed);
    get_segwit_p2wpkh_address(&p2wpkh, &public_key_compressed);

    printf("\n");

    bnz_print(&public_key_compressed, 16, "PUBLIC KEY (COMPRESSED): ");
    bnz_print(&p2pkh, 58, "P2PKH ADDRESS: 1"); // need to print 1 before the P2PKH address because it corresponds to a leading zero at the msb end when treated as a number
    print_segwit_p2wpkh_address(&p2wpkh, "SEGWIT P2WPKH ADDRESS: ");

    printf("\n");

    bnz_free(&private_key_wif);
    bnz_free(&private_key);
    bnz_free(&public_key_compressed);
    bnz_free(&p2pkh);
    bnz_free(&p2wpkh);
    bnz_free(&public_key.x);
    bnz_free(&public_key.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

void menu_4_5_secp256k1_point_addition(const char *version)
{
    uint8_t a_x_str[67], a_y_str[67], b_x_str[67], b_y_str[67];
    PT a, b, c;
    bnz_t private_key;

    SECP256K1 secp256k1;

    secp256k1 = secp256k1_init();

    bnz_init(&a.x);
    bnz_init(&a.y);
    bnz_init(&b.x);
    bnz_init(&b.y);
    bnz_init(&c.x);
    bnz_init(&c.y);

    printf("Point 1 x: ");
    get_str_input(a_x_str, 66);
    bnz_set_str(&a.x, a_x_str, 16);

    printf("Point 1 y: ");
    get_str_input(a_y_str, 66);
    bnz_set_str(&a.y, a_y_str, 16);

    printf("Point 2 x: ");
    get_str_input(b_x_str, 66);
    bnz_set_str(&b.x, b_x_str, 16);

    printf("Point 2 y: ");
    get_str_input(b_y_str, 66);
    bnz_set_str(&b.y, b_y_str, 16);

    secp256k1_point_addition(secp256k1, &a, &b, &c);

    system("cls");
    printf("%s\n\n", version);

    printf("POINT 1:\n");
    bnz_print(&a.x, 16, "x: ");
    bnz_print(&a.y, 16, "y: ");
    printf("\n");

    printf("POINT 2:\n");
    bnz_print(&b.x, 16, "x: ");
    bnz_print(&b.y, 16, "y: ");
    printf("\n");

    printf("POINT 1 + POINT 2:\n");
    bnz_print(&c.x, 16, "x: ");
    bnz_print(&c.y, 16, "y: ");
    printf("\n");

    secp256k1_free(secp256k1);

    bnz_free(&a.x);
    bnz_free(&a.y);
    bnz_free(&b.x);
    bnz_free(&b.y);
    bnz_free(&c.x);
    bnz_free(&c.y);

    printf("press any key to continue...");

    getchar();
}

void menu_4_6_secp256k1_point_doubling(const char *version)
{
    uint8_t a_x_str[67], a_y_str[67];
    PT a, b;
    bnz_t private_key;

    SECP256K1 secp256k1;

    secp256k1 = secp256k1_init();

    bnz_init(&a.x);
    bnz_init(&a.y);
    bnz_init(&b.x);
    bnz_init(&b.y);

    printf("Point x: ");
    get_str_input(a_x_str, 66);
    bnz_set_str(&a.x, a_x_str, 16);

    printf("Point y: ");
    get_str_input(a_y_str, 66);
    bnz_set_str(&a.y, a_y_str, 16);

    secp256k1_point_doubling(secp256k1, &a, &b);

    system("cls");
    printf("%s\n\n", version);

    printf("POINT:\n");
    bnz_print(&a.x, 16, "x: ");
    bnz_print(&a.y, 16, "y: ");
    printf("\n");

    printf("DOUBLED POINT:\n");
    bnz_print(&b.x, 16, "x: ");
    bnz_print(&b.y, 16, "y: ");
    printf("\n");

    secp256k1_free(secp256k1);

    bnz_free(&a.x);
    bnz_free(&a.y);
    bnz_free(&b.x);
    bnz_free(&b.y);

    printf("press any key to continue...");

    getchar();
}

void menu_4_7_secp256k1_scalar_multiplication(const char *version)
{
    uint8_t multiplier_str[67];
    bnz_t multiplier;
    PT p;

    bnz_init(&multiplier);
    bnz_init(&p.x);
    bnz_init(&p.y);

    SECP256K1 secp256k1;

    secp256k1 = secp256k1_init();

    system("cls");
    printf("%s\n\n", version);

    printf("Multiplier: ");
    get_str_input(multiplier_str, 66);
    bnz_set_str(&multiplier, multiplier_str, 16);

    system("cls");
    printf("%s\n\n", version);

    if (bnz_cmp_bnz(&multiplier, &secp256k1.n) != -1) {
        bnz_mod_bnz(&multiplier, &multiplier, &secp256k1.n);
        bnz_print(&multiplier, 16, "MULTIPLIER (MOD SECP256K1 MODULUS): ");
    } else {
        bnz_print(&multiplier, 16, "MULTIPLIER: ");
    }

    printf("\n");

    secp256k1_scalar_multiplication(secp256k1, &multiplier, &p);

    printf("SECP256K1 POINT:\n");
    bnz_print(&p.x, 16, " x: ");
    bnz_print(&p.y, 16, " y: ");
    printf("\n");

    bnz_free(&multiplier);
    bnz_free(&p.x);
    bnz_free(&p.y);

    secp256k1_free(secp256k1);

    printf("press any key to continue...");

    getchar();
}

/* MAIN */

int main()
{
    static char *version = "bitcoin_math\nv0.15, 2025-07-07";
    int menu, running = 1;
    while (running) {
        system("cls");
        printf("%s\n\n", version);
        printf("1. Master keys\n");
        printf("2. Child keys\n");
        printf("3. Base converter\n");
        printf("4. Functions\n");
        printf("\n");
        menu = get_num_input(1, 0, 4);
        switch (menu) {
            case 1:
                menu_1_master_keys(version);
                break;
            case 2:
                menu_2_child_keys(version);
                break;
            case 3:
                menu_3_base_converter(version);
                break;
            case 4:
                menu_4_functions(version);
                break;
            default:
                running = 0;
                break;
        }
    }
    return 0;
}
