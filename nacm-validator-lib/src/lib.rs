//! # NACM Validator - Network Access Control Model with Tail-f ACM Extensions
//!
//! This library implements NACM (RFC 8341) access control validation in Rust with comprehensive
//! support for Tail-f ACM (Access Control Model) extensions. It provides functionality to:
//!
//! ## Core NACM Features (RFC 8341)
//! - Parse real-world NACM XML configurations
//! - Validate access requests against defined rules
//! - Handle user groups and rule precedence
//! - Support various operations (CRUD + exec) and path matching
//!
//! ## Tail-f ACM Extensions
//! - **Command Rules**: Context-aware command access control (CLI, WebUI, NETCONF)
//! - **Enhanced Logging**: Granular logging control with `log-if-*` attributes
//! - **ValidationResult**: Returns both access decision and logging indication
//! - **Group ID Mapping**: External authentication system integration via GID
//! - **Context Awareness**: Different access policies for different user interfaces
//!
//! ## Quick Start
//!
//! ### Standard NACM Data Access Validation
//! 
//! ```rust
//! use nacm_validator::{NacmConfig, AccessRequest, Operation, RequestContext};
//!
//! // Load configuration from XML
//! let xml_content = r#"<?xml version="1.0" encoding="UTF-8"?>
//! <config xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
//!   <nacm>
//!     <enable-nacm>true</enable-nacm>
//!     <read-default>permit</read-default>
//!     <write-default>deny</write-default>
//!     <exec-default>permit</exec-default>
//!     <groups>
//!       <group>
//!         <name>admin</name>
//!         <user-name>alice</user-name>
//!       </group>
//!     </groups>
//!     <rule-list>
//!       <name>admin-acl</name>
//!       <group>admin</group>
//!       <rule>
//!         <name>permit-all</name>
//!         <action>permit</action>
//!       </rule>
//!     </rule-list>
//!   </nacm>
//! </config>"#;
//! let config = NacmConfig::from_xml(&xml_content)?;
//!
//! // Create a data access request
//! let context = RequestContext::NETCONF;
//! let request = AccessRequest {
//!     user: "alice",
//!     module_name: Some("ietf-interfaces"),
//!     rpc_name: None,
//!     operation: Operation::Read,
//!     path: Some("/interfaces"),
//!     context: Some(&context),
//!     command: None,
//! };
//!
//! // Validate the request - returns ValidationResult with access decision and logging info
//! let result = config.validate(&request);
//! println!("Access {}: {}", 
//!          if result.effect == nacm_validator::RuleEffect::Permit { "PERMIT" } else { "DENY" },
//!          if result.should_log { "[LOGGED]" } else { "" });
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Tail-f ACM Command Access Validation
//!
//! ```rust
//! use nacm_validator::{NacmConfig, AccessRequest, Operation, RequestContext};
//!
//! // Load configuration with Tail-f ACM command rules
//! let xml_content = r#"<?xml version="1.0" encoding="UTF-8"?>
//! <config xmlns="http://tail-f.com/ns/config/1.0">
//!     <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
//!         <enable-nacm>true</enable-nacm>
//!         <read-default>deny</read-default>
//!         <write-default>deny</write-default>
//!         <exec-default>deny</exec-default>
//!         <cmd-read-default xmlns="http://tail-f.com/yang/acm">permit</cmd-read-default>
//!         <cmd-exec-default xmlns="http://tail-f.com/yang/acm">deny</cmd-exec-default>
//!         <groups>
//!             <group>
//!                 <name>admin</name>
//!                 <user-name>alice</user-name>
//!             </group>
//!         </groups>
//!         <rule-list>
//!             <name>admin-rules</name>
//!             <group>admin</group>
//!             <cmdrule xmlns="http://tail-f.com/yang/acm">
//!                 <name>cli-show</name>
//!                 <context>cli</context>
//!                 <command>show *</command>
//!                 <action>permit</action>
//!             </cmdrule>
//!         </rule-list>
//!     </nacm>
//! </config>"#;
//! let config = NacmConfig::from_xml(&xml_content)?;
//!
//! // Create a command access request
//! let context = RequestContext::CLI;
//! let request = AccessRequest {
//!     user: "alice",
//!     module_name: None,
//!     rpc_name: None,
//!     operation: Operation::Read,
//!     path: None,
//!     context: Some(&context),
//!     command: Some("show status"),
//! };
//!
//! // Validate command access using Tail-f ACM command rules
//! let result = config.validate(&request);
//! match result.effect {
//!     nacm_validator::RuleEffect::Permit => {
//!         println!("Command access PERMITTED{}", 
//!                 if result.should_log { " [LOGGED]" } else { "" });
//!     },
//!     nacm_validator::RuleEffect::Deny => {
//!         println!("Command access DENIED{}", 
//!                 if result.should_log { " [LOGGED]" } else { "" });
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// NACM Rule effect (permit or deny)
/// 
/// This enum represents the final decision for an access request.
/// In NACM, every rule must have an action that either permits or denies access.
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::RuleEffect;
/// 
/// let permit = RuleEffect::Permit;
/// let deny = RuleEffect::Deny;
/// 
/// // Rules with permit effects allow access
/// assert_eq!(permit == RuleEffect::Permit, true);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")] // Serializes as "permit"/"deny" in JSON/XML
pub enum RuleEffect {
    /// Allow the requested access
    Permit,
    /// Deny the requested access
    Deny,
}

/// Access control validation result with logging indication
/// 
/// This structure contains both the access control decision and whether
/// the decision should be logged according to the configured logging rules.
/// This supports the Tail-f ACM extensions that provide fine-grained control
/// over access control logging.
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::{ValidationResult, RuleEffect};
/// 
/// let result = ValidationResult {
///     effect: RuleEffect::Permit,
///     should_log: true,
/// };
/// 
/// if result.should_log {
///     println!("Access {}: should be logged", 
///              if result.effect == RuleEffect::Permit { "permitted" } else { "denied" });
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationResult {
    /// The access control decision
    pub effect: RuleEffect,
    /// Whether this decision should be logged
    pub should_log: bool,
}

/// Implementation of `FromStr` trait for `RuleEffect`
/// 
/// This allows parsing rule effects from strings (used when parsing XML).
/// Case-insensitive parsing: "PERMIT", "permit", "Permit" all work.
impl std::str::FromStr for RuleEffect {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "permit" => Ok(RuleEffect::Permit),
            "deny" => Ok(RuleEffect::Deny),
            _ => Err(format!("Unknown rule effect: {}", s)),
        }
    }
}

/// NACM operations enumeration
/// 
/// Represents the different types of operations that can be performed
/// in a NETCONF/RESTCONF system. Maps to standard CRUD operations plus exec.
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::Operation;
/// 
/// let read_op = Operation::Read;
/// let write_op = Operation::Update;
/// 
/// // Operations can be compared
/// assert_ne!(read_op, write_op);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Reading/retrieving data (GET operations)
    Read,
    /// Creating new data (POST operations)
    Create,
    /// Modifying existing data (PUT/PATCH operations)
    Update,
    /// Removing data (DELETE operations)
    Delete,
    /// Executing RPCs or actions (RPC operations)
    Exec,
}

/// Request context enumeration
/// 
/// Represents the different management interfaces or contexts from which
/// an access request originates. This is part of the Tail-f ACM extensions
/// that enable context-specific access control rules.
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::RequestContext;
/// 
/// let cli_context = RequestContext::CLI;
/// let netconf_context = RequestContext::NETCONF;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestContext {
    /// NETCONF protocol access
    NETCONF,
    /// Command-line interface access
    CLI,
    /// Web-based user interface access
    WebUI,
    /// Other/custom interface
    Other(String),
}

impl RequestContext {
    /// Check if this context matches a pattern
    /// 
    /// Supports wildcard matching where "*" matches any context.
    /// 
    /// # Arguments
    /// 
    /// * `pattern` - The pattern to match against (e.g., "cli", "*", "webui")
    /// 
    /// # Returns
    /// 
    /// * `true` if the context matches the pattern
    /// * `false` otherwise
    pub fn matches(&self, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        
        match self {
            RequestContext::NETCONF => pattern.eq_ignore_ascii_case("netconf"),
            RequestContext::CLI => pattern.eq_ignore_ascii_case("cli"),
            RequestContext::WebUI => pattern.eq_ignore_ascii_case("webui"),
            RequestContext::Other(name) => pattern.eq_ignore_ascii_case(name),
        }
    }
}

/// Implementation of `FromStr` trait for `Operation`
/// 
/// Enables parsing operations from strings, used in CLI and XML parsing.
/// Case-insensitive: "READ", "read", "Read" all parse to `Operation::Read`.
impl std::str::FromStr for Operation {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "read" => Ok(Operation::Read),
            "create" => Ok(Operation::Create),
            "update" => Ok(Operation::Update),
            "delete" => Ok(Operation::Delete),
            "exec" => Ok(Operation::Exec),
            _ => Err(format!("Unknown operation: {}", s)),
        }
    }
}

/// NACM Rule structure (extended to match XML format)
/// 
/// Represents a single NACM access control rule. Each rule defines:
/// - What it applies to (module, RPC, path)
/// - Which operations it covers
/// - Whether it permits or denies access
/// - Its precedence order (lower numbers = higher priority)
/// 
/// # Fields
/// 
/// * `name` - Human-readable identifier for the rule
/// * `module_name` - YANG module this rule applies to (None = any module)
/// * `rpc_name` - Specific RPC name (None = any RPC, "*" = wildcard)
/// * `path` - XPath or data path (None = any path, "/" = root)
/// * `access_operations` - Set of operations this rule covers
/// * `effect` - Whether to permit or deny matching requests
/// * `order` - Rule precedence (lower = higher priority)
/// * `context` - Request context this rule applies to (Tail-f extension)
/// * `log_if_permit` - Log when this rule permits access (Tail-f extension)
/// * `log_if_deny` - Log when this rule denies access (Tail-f extension)
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::{NacmRule, RuleEffect, Operation};
/// use std::collections::HashSet;
/// 
/// let mut ops = HashSet::new();
/// ops.insert(Operation::Read);
/// 
/// let rule = NacmRule {
///     name: "allow-read-interfaces".to_string(),
///     module_name: Some("ietf-interfaces".to_string()),
///     rpc_name: None,
///     path: Some("/interfaces".to_string()),
///     access_operations: ops,
///     effect: RuleEffect::Permit,
///     order: 10,
///     context: None,
///     log_if_permit: false,
///     log_if_deny: false,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NacmRule {
    /// Unique name for this rule
    pub name: String,
    /// YANG module name this rule applies to (None = any module)
    pub module_name: Option<String>,
    /// RPC name this rule applies to (None = any RPC)
    pub rpc_name: Option<String>,
    /// XPath or data path (None = any path)
    pub path: Option<String>,
    /// Set of operations covered by this rule
    pub access_operations: HashSet<Operation>,
    /// Whether this rule permits or denies access
    pub effect: RuleEffect,
    /// Rule precedence - lower numbers have higher priority
    pub order: u32,
    /// Request context pattern this rule applies to (Tail-f extension)
    pub context: Option<String>,
    /// Log when this rule permits access (Tail-f extension)
    pub log_if_permit: bool,
    /// Log when this rule denies access (Tail-f extension)
    pub log_if_deny: bool,
}

/// NACM Command Rule structure (Tail-f ACM extension)
/// 
/// Represents a command-based access control rule for CLI and Web UI operations.
/// Command rules complement standard NACM data access rules by controlling
/// access to management commands that don't map to NETCONF operations.
/// 
/// # Fields
/// 
/// * `name` - Human-readable identifier for the command rule
/// * `context` - Management interface pattern (e.g., "cli", "webui", "*")
/// * `command` - Command pattern to match (supports wildcards)
/// * `access_operations` - Set of command operations (read, exec)
/// * `effect` - Whether to permit or deny matching command requests
/// * `order` - Rule precedence within the rule list
/// * `log_if_permit` - Log when this rule permits access
/// * `log_if_deny` - Log when this rule denies access
/// * `comment` - Optional description of the rule
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::{NacmCommandRule, RuleEffect, Operation};
/// use std::collections::HashSet;
/// 
/// let mut ops = HashSet::new();
/// ops.insert(Operation::Read);
/// ops.insert(Operation::Exec);
/// 
/// let cmd_rule = NacmCommandRule {
///     name: "cli-show-status".to_string(),
///     context: Some("cli".to_string()),
///     command: Some("show status".to_string()),
///     access_operations: ops,
///     effect: RuleEffect::Permit,
///     order: 10,
///     log_if_permit: true,
///     log_if_deny: false,
///     comment: Some("Allow operators to view system status".to_string()),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NacmCommandRule {
    /// Unique name for this command rule
    pub name: String,
    /// Management interface pattern (e.g., "cli", "webui", "*")
    pub context: Option<String>,
    /// Command pattern to match (supports wildcards)
    pub command: Option<String>,
    /// Set of command operations covered by this rule
    pub access_operations: HashSet<Operation>,
    /// Whether this rule permits or denies access
    pub effect: RuleEffect,
    /// Rule precedence within the rule list
    pub order: u32,
    /// Log when this rule permits access
    pub log_if_permit: bool,
    /// Log when this rule denies access
    pub log_if_deny: bool,
    /// Optional description of the rule
    pub comment: Option<String>,
}

/// NACM Rule List with associated groups
/// 
/// A rule list is a named collection of rules that applies to specific user groups.
/// Rule lists are processed in order, and within each list, rules are ordered by priority.
/// 
/// # Fields
/// 
/// * `name` - Identifier for this rule list
/// * `groups` - User groups this rule list applies to
/// * `rules` - Ordered list of access control rules
/// * `command_rules` - Ordered list of command access control rules (Tail-f extension)
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::{NacmRuleList, NacmRule, NacmCommandRule, RuleEffect, Operation};
/// use std::collections::HashSet;
/// 
/// let rule_list = NacmRuleList {
///     name: "admin-rules".to_string(),
///     groups: vec!["admin".to_string()],
///     rules: vec![], // Would contain actual rules
///     command_rules: vec![], // Would contain command rules
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NacmRuleList {
    /// Name of this rule list
    pub name: String,
    /// User groups this rule list applies to
    pub groups: Vec<String>,
    /// Ordered list of rules in this list
    pub rules: Vec<NacmRule>,
    /// Ordered list of command rules in this list (Tail-f extension)
    pub command_rules: Vec<NacmCommandRule>,
}

/// NACM Group definition
/// 
/// Represents a named group of users. Groups are used to organize users
/// and apply rule lists to multiple users at once.
/// 
/// # Fields
/// 
/// * `name` - Group identifier (e.g., "admin", "operators")
/// * `users` - List of usernames belonging to this group
/// * `gid` - Optional numerical group ID for OS integration (Tail-f extension)
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::NacmGroup;
/// 
/// let admin_group = NacmGroup {
///     name: "admin".to_string(),
///     users: vec!["alice".to_string(), "bob".to_string()],
///     gid: Some(1000),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NacmGroup {
    /// Name of the group
    pub name: String,
    /// List of usernames in this group
    pub users: Vec<String>,
    /// Optional numerical group ID for OS integration (Tail-f extension)
    pub gid: Option<i32>,
}

/// Full NACM configuration
/// 
/// The main configuration object that contains all NACM settings:
/// - Global enable/disable flag
/// - Default policies for different operation types
/// - User groups and their members
/// - Rule lists with access control rules
/// 
/// # Fields
/// 
/// * `enable_nacm` - Global NACM enable flag
/// * `read_default` - Default policy for read operations
/// * `write_default` - Default policy for write operations (create/update/delete)
/// * `exec_default` - Default policy for exec operations (RPC calls)
/// * `cmd_read_default` - Default policy for command read operations (Tail-f extension)
/// * `cmd_exec_default` - Default policy for command exec operations (Tail-f extension)
/// * `log_if_default_permit` - Log when default policies permit access (Tail-f extension)
/// * `log_if_default_deny` - Log when default policies deny access (Tail-f extension)
/// * `groups` - Map of group names to group definitions
/// * `rule_lists` - List of rule lists, processed in order
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::{NacmConfig, RuleEffect};
/// use std::collections::HashMap;
/// 
/// let config = NacmConfig {
///     enable_nacm: true,
///     read_default: RuleEffect::Deny,
///     write_default: RuleEffect::Deny,
///     exec_default: RuleEffect::Deny,
///     cmd_read_default: RuleEffect::Permit,
///     cmd_exec_default: RuleEffect::Permit,
///     log_if_default_permit: false,
///     log_if_default_deny: false,
///     groups: HashMap::new(),
///     rule_lists: vec![],
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NacmConfig {
    /// Global NACM enable flag - if false, all access is permitted
    pub enable_nacm: bool,
    /// Default policy for read operations when no rules match
    pub read_default: RuleEffect,
    /// Default policy for write operations (create/update/delete) when no rules match
    pub write_default: RuleEffect,
    /// Default policy for exec operations (RPCs) when no rules match
    pub exec_default: RuleEffect,
    /// Default policy for command read operations when no command rules match (Tail-f extension)
    pub cmd_read_default: RuleEffect,
    /// Default policy for command exec operations when no command rules match (Tail-f extension)
    pub cmd_exec_default: RuleEffect,
    /// Log when default policies permit access (Tail-f extension)
    pub log_if_default_permit: bool,
    /// Log when default policies deny access (Tail-f extension)
    pub log_if_default_deny: bool,
    /// Map of group name to group definition
    pub groups: HashMap<String, NacmGroup>,
    /// Ordered list of rule lists
    pub rule_lists: Vec<NacmRuleList>,
}

/// Represents an access request for validation
/// 
/// This structure contains all the information needed to validate
/// an access request against NACM rules. Uses borrowed string slices
/// for efficiency (avoids copying strings).
/// 
/// # Lifetimes
/// 
/// The `'a` lifetime parameter ensures that this struct doesn't outlive
/// the data it references. This is Rust's way of preventing dangling pointers.
/// 
/// # Fields
/// 
/// * `user` - Username making the request
/// * `module_name` - YANG module being accessed (if applicable)
/// * `rpc_name` - RPC being called (if applicable)
/// * `operation` - Type of operation being performed
/// * `path` - Data path being accessed (if applicable)
/// * `context` - Request context (NETCONF, CLI, WebUI, etc.) - Tail-f extension
/// * `command` - Command being executed (for command rules) - Tail-f extension
/// 
/// # Examples
/// 
/// ```
/// use nacm_validator::{AccessRequest, Operation, RequestContext};
/// 
/// let request = AccessRequest {
///     user: "alice",
///     module_name: Some("ietf-interfaces"),
///     rpc_name: None,
///     operation: Operation::Read,
///     path: Some("/interfaces/interface[name='eth0']"),
///     context: Some(&RequestContext::NETCONF),
///     command: None,
/// };
/// ```
pub struct AccessRequest<'a> {
    /// Username making the access request
    pub user: &'a str,
    /// YANG module name being accessed (None if not module-specific)
    pub module_name: Option<&'a str>,
    /// RPC name being called (None if not an RPC call)
    pub rpc_name: Option<&'a str>,
    /// Type of operation being performed
    pub operation: Operation,
    /// XPath or data path being accessed (None if not path-specific)
    pub path: Option<&'a str>,
    /// Request context (NETCONF, CLI, WebUI, etc.) - Tail-f extension
    pub context: Option<&'a RequestContext>,
    /// Command being executed (for command rules) - Tail-f extension
    pub command: Option<&'a str>,
}

// ============================================================================
// XML Parsing Structures
// ============================================================================
//
// The following structures are used internally for parsing XML configuration
// files. They mirror the XML schema and use serde attributes to handle
// the conversion from XML elements to Rust structs.
//
// These are separate from the main API structs to:
// 1. Handle XML-specific naming (kebab-case vs snake_case)
// 2. Deal with XML structure differences (nested elements, attributes)
// 3. Keep the public API clean and independent of XML format
//
// The #[derive(Deserialize)] enables automatic XML parsing via serde-xml-rs.
// The #[serde(rename = "...")] attributes map XML element names to Rust fields.
// ============================================================================

/// Root XML configuration element
/// 
/// Maps to the top-level `<config>` element in NACM XML files.
/// Contains the main `<nacm>` configuration block.
#[derive(Debug, Deserialize)]
struct XmlConfig {
    /// The main NACM configuration block
    #[serde(rename = "nacm")]
    pub nacm: XmlNacm,
}

/// Main NACM configuration element from XML
/// 
/// Maps to the `<nacm>` element and contains all NACM settings:
/// global flags, default policies, groups, and rule lists.
#[derive(Debug, Deserialize)]
struct XmlNacm {
    /// Global NACM enable flag (XML: <enable-nacm>)
    #[serde(rename = "enable-nacm")]
    pub enable_nacm: bool,
    /// Default policy for read operations (XML: <read-default>)
    #[serde(rename = "read-default")]
    pub read_default: String,
    /// Default policy for write operations (XML: <write-default>)
    #[serde(rename = "write-default")]
    pub write_default: String,
    /// Default policy for exec operations (XML: <exec-default>)
    #[serde(rename = "exec-default")]
    pub exec_default: String,
    /// Default policy for command read operations (XML: <cmd-read-default>) - Tail-f extension
    #[serde(rename = "cmd-read-default", default = "default_permit")]
    pub cmd_read_default: String,
    /// Default policy for command exec operations (XML: <cmd-exec-default>) - Tail-f extension
    #[serde(rename = "cmd-exec-default", default = "default_permit")]
    pub cmd_exec_default: String,
    /// Log when default policies permit access (XML: <log-if-default-permit/>) - Tail-f extension
    #[serde(rename = "log-if-default-permit", default)]
    pub log_if_default_permit: Option<()>,
    /// Log when default policies deny access (XML: <log-if-default-deny/>) - Tail-f extension
    #[serde(rename = "log-if-default-deny", default)]
    pub log_if_default_deny: Option<()>,
    /// Container for all groups (XML: <groups>)
    pub groups: XmlGroups,
    /// List of rule lists (XML: <rule-list> elements)
    #[serde(rename = "rule-list")]
    pub rule_lists: Vec<XmlRuleList>,
}

/// Default function for cmd-read-default and cmd-exec-default
fn default_permit() -> String {
    "permit".to_string()
}

/// Container for group definitions from XML
/// 
/// Maps to the `<groups>` element which contains multiple `<group>` elements.
#[derive(Debug, Deserialize)]
struct XmlGroups {
    /// List of individual group definitions
    pub group: Vec<XmlGroup>,
}

/// Individual group definition from XML
/// 
/// Maps to a `<group>` element containing group name and user list.
#[derive(Debug, Deserialize)]
struct XmlGroup {
    /// Group name (XML: <name>)
    pub name: String,
    /// List of usernames in this group (XML: <user-name> elements)
    /// The `default` attribute provides an empty vector if no users are specified
    #[serde(rename = "user-name", default)]
    pub user_names: Vec<String>,
    /// Optional numerical group ID (XML: <gid>) - Tail-f extension
    #[serde(default)]
    pub gid: Option<i32>,
}

/// Rule list definition from XML
/// 
/// Maps to a `<rule-list>` element containing the rule list metadata
/// and the actual access control rules.
#[derive(Debug, Deserialize)]
struct XmlRuleList {
    /// Rule list name (XML: <name>)
    pub name: String,
    /// Group this rule list applies to (XML: <group>)
    pub group: String,
    /// List of rules in this rule list (XML: <rule> elements)
    /// The `default` attribute provides an empty vector if no rules are specified
    #[serde(default)]
    pub rule: Vec<XmlRule>,
    /// List of command rules in this rule list (XML: <cmdrule> elements) - Tail-f extension
    #[serde(default)]
    pub cmdrule: Vec<XmlCommandRule>,
}

/// Individual access control rule from XML
/// 
/// Maps to a `<rule>` element with all its sub-elements.
/// Optional fields use `Option<T>` to handle missing XML elements.
#[derive(Debug, Deserialize)]
struct XmlRule {
    /// Rule name (XML: <name>)
    pub name: String,
    /// YANG module name this rule applies to (XML: <module-name>)
    #[serde(rename = "module-name")]
    pub module_name: Option<String>,
    /// RPC name this rule applies to (XML: <rpc-name>)
    #[serde(rename = "rpc-name")]
    pub rpc_name: Option<String>,
    /// XPath or data path (XML: <path>)
    pub path: Option<String>,
    /// Space-separated list of operations (XML: <access-operations>)
    #[serde(rename = "access-operations")]
    pub access_operations: Option<String>,
    /// Rule effect: "permit" or "deny" (XML: <action>)
    pub action: String,
    /// Request context pattern (XML: <context>) - Tail-f extension
    #[serde(default)]
    pub context: Option<String>,
    /// Log when this rule permits access (XML: <log-if-permit/>) - Tail-f extension
    #[serde(rename = "log-if-permit", default)]
    pub log_if_permit: Option<()>,
    /// Log when this rule denies access (XML: <log-if-deny/>) - Tail-f extension
    #[serde(rename = "log-if-deny", default)]
    pub log_if_deny: Option<()>,
}

/// Individual command access control rule from XML (Tail-f extension)
/// 
/// Maps to a `<cmdrule>` element with all its sub-elements.
/// Optional fields use `Option<T>` to handle missing XML elements.
#[derive(Debug, Deserialize)]
struct XmlCommandRule {
    /// Command rule name (XML: <name>)
    pub name: String,
    /// Management interface pattern (XML: <context>)
    #[serde(default)]
    pub context: Option<String>,
    /// Command pattern to match (XML: <command>)
    #[serde(default)]
    pub command: Option<String>,
    /// Space-separated list of command operations (XML: <access-operations>)
    #[serde(rename = "access-operations")]
    pub access_operations: Option<String>,
    /// Rule effect: "permit" or "deny" (XML: <action>)
    pub action: String,
    /// Log when this rule permits access (XML: <log-if-permit/>)
    #[serde(rename = "log-if-permit", default)]
    pub log_if_permit: Option<()>,
    /// Log when this rule denies access (XML: <log-if-deny/>)
    #[serde(rename = "log-if-deny", default)]
    pub log_if_deny: Option<()>,
    /// Optional description (XML: <comment>)
    #[serde(default)]
    pub comment: Option<String>,
}

impl NacmConfig {
    /// Merge multiple NACM configurations into a single configuration
    /// 
    /// Implements YANG merge semantics where:
    /// - Leaf values (global settings) use last-wins strategy
    /// - List elements (groups, rules) are merged additively
    /// - Rule precedence is adjusted based on source file ordering
    /// 
    /// # Arguments
    /// 
    /// * `configs` - Vector of (config, file_index) tuples where file_index determines precedence
    /// 
    /// # Returns
    /// 
    /// * `Ok(NacmConfig)` - Successfully merged configuration
    /// * `Err(Box<dyn Error>)` - Merge operation failed
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use nacm_validator::NacmConfig;
    /// 
    /// let xml1 = r#"<config xmlns="http://tail-f.com/ns/config/1.0">
    ///   <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
    ///     <enable-nacm>true</enable-nacm>
    ///     <read-default>deny</read-default>
    ///     <write-default>deny</write-default>
    ///     <exec-default>deny</exec-default>
    ///     <groups><group><name>admin</name><user-name>alice</user-name></group></groups>
    ///     <rule-list><name>admin-rules</name><group>admin</group></rule-list>
    ///   </nacm>
    /// </config>"#;
    /// let xml2 = r#"<config xmlns="http://tail-f.com/ns/config/1.0">
    ///   <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
    ///     <enable-nacm>true</enable-nacm>
    ///     <read-default>permit</read-default>
    ///     <write-default>deny</write-default>
    ///     <exec-default>deny</exec-default>
    ///     <groups><group><name>ops</name><user-name>bob</user-name></group></groups>
    ///     <rule-list><name>ops-rules</name><group>ops</group></rule-list>
    ///   </nacm>
    /// </config>"#;
    /// 
    /// let config1 = NacmConfig::from_xml(xml1).unwrap();
    /// let config2 = NacmConfig::from_xml(xml2).unwrap();
    /// 
    /// let merged = NacmConfig::merge(vec![
    ///     (config1, 0),
    ///     (config2, 1),
    /// ]).unwrap();
    /// assert_eq!(merged.groups.len(), 2); // Both groups merged
    /// ```
    pub fn merge(configs: Vec<(NacmConfig, usize)>) -> Result<Self, Box<dyn std::error::Error>> {
        if configs.is_empty() {
            return Err("Cannot merge empty configuration list".into());
        }
        
        if configs.len() == 1 {
            return Ok(configs.into_iter().next().unwrap().0);
        }
        
        // Start with default configuration
        let mut merged = Self::default();
        
        // Merge each configuration in order
        for (config, file_index) in configs {
            merged = merged.merge_single_config(config, file_index)?;
        }
        
        Ok(merged)
    }
    
    /// Create a default NACM configuration
    /// 
    /// Returns a configuration with reasonable defaults:
    /// - NACM enabled
    /// - All operations denied by default
    /// - No logging by default
    /// - Empty groups and rule lists
    pub fn default() -> Self {
        Self {
            enable_nacm: true,
            read_default: RuleEffect::Deny,
            write_default: RuleEffect::Deny,
            exec_default: RuleEffect::Deny,
            cmd_read_default: RuleEffect::Permit,
            cmd_exec_default: RuleEffect::Permit,
            log_if_default_permit: false,
            log_if_default_deny: false,
            groups: HashMap::new(),
            rule_lists: Vec::new(),
        }
    }
    
    /// Merge a single configuration into this one
    /// 
    /// # Arguments
    /// 
    /// * `other` - Configuration to merge into this one
    /// * `file_index` - Index used for rule precedence adjustment
    /// 
    /// # Returns
    /// 
    /// * `Result<NacmConfig, Box<dyn Error>>` - Merged configuration or error
    fn merge_single_config(mut self, other: NacmConfig, file_index: usize) -> Result<Self, Box<dyn std::error::Error>> {
        // Merge leaf values (last-wins strategy)
        self.enable_nacm = other.enable_nacm;
        self.read_default = other.read_default;
        self.write_default = other.write_default;
        self.exec_default = other.exec_default;
        self.cmd_read_default = other.cmd_read_default;
        self.cmd_exec_default = other.cmd_exec_default;
        self.log_if_default_permit = other.log_if_default_permit;
        self.log_if_default_deny = other.log_if_default_deny;
        
        // Merge groups (additive)
        for (group_name, group) in other.groups {
            if self.groups.contains_key(&group_name) {
                // Group exists - merge users additively
                self.merge_group(&group_name, group)?;
            } else {
                // New group - add directly
                self.groups.insert(group_name, group);
            }
        }
        
        // Merge rule lists (additive with precedence adjustment)
        for mut rule_list in other.rule_lists {
            // Adjust rule precedence based on file order
            self.adjust_rule_orders(&mut rule_list, file_index);
            
            // Check if rule list with same name exists
            if let Some(existing_idx) = self.rule_lists.iter().position(|rl| rl.name == rule_list.name) {
                // Merge with existing rule list
                self.merge_rule_list(existing_idx, rule_list)?;
            } else {
                // New rule list - add directly
                self.rule_lists.push(rule_list);
            }
        }
        
        Ok(self)
    }
    
    /// Merge a group with an existing group
    /// 
    /// # Arguments
    /// 
    /// * `group_name` - Name of the group to merge
    /// * `new_group` - Group data to merge in
    /// 
    /// # Returns
    /// 
    /// * `Result<(), Box<dyn Error>>` - Success or error
    fn merge_group(&mut self, group_name: &str, new_group: NacmGroup) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(existing_group) = self.groups.get_mut(group_name) {
            // Merge users additively (avoid duplicates)
            for user in new_group.users {
                if !existing_group.users.contains(&user) {
                    existing_group.users.push(user);
                }
            }
            
            // Update GID if provided (last-wins)
            if new_group.gid.is_some() {
                existing_group.gid = new_group.gid;
            }
        }
        Ok(())
    }
    
    /// Adjust rule orders based on file index
    /// 
    /// Rules from files loaded later get higher precedence numbers,
    /// ensuring that rules from earlier files take precedence.
    /// 
    /// # Arguments
    /// 
    /// * `rule_list` - Rule list to adjust
    /// * `file_index` - File index for precedence calculation
    fn adjust_rule_orders(&self, rule_list: &mut NacmRuleList, file_index: usize) {
        // Adjust regular rules
        for rule in &mut rule_list.rules {
            rule.order = (file_index as u32) * 10000 + rule.order;
        }
        
        // Adjust command rules
        for cmd_rule in &mut rule_list.command_rules {
            cmd_rule.order = (file_index as u32) * 10000 + cmd_rule.order;
        }
    }
    
    /// Merge a rule list with an existing rule list
    /// 
    /// # Arguments
    /// 
    /// * `existing_idx` - Index of existing rule list
    /// * `new_rule_list` - New rule list to merge in
    /// 
    /// # Returns
    /// 
    /// * `Result<(), Box<dyn Error>>` - Success or error
    fn merge_rule_list(&mut self, existing_idx: usize, new_rule_list: NacmRuleList) -> Result<(), Box<dyn std::error::Error>> {
        let existing = &mut self.rule_lists[existing_idx];
        
        // Merge groups additively
        for group in new_rule_list.groups {
            if !existing.groups.contains(&group) {
                existing.groups.push(group);
            }
        }
        
        // Merge rules additively
        existing.rules.extend(new_rule_list.rules);
        
        // Merge command rules additively
        existing.command_rules.extend(new_rule_list.command_rules);
        
        Ok(())
    }

    /// Parse NACM configuration from XML string
    /// 
    /// This function takes an XML string containing NACM configuration
    /// and parses it into a `NacmConfig` struct. It handles the conversion
    /// from the XML schema to our internal representation.
    /// 
    /// # Arguments
    /// 
    /// * `xml_content` - String slice containing the XML configuration
    /// 
    /// # Returns
    /// 
    /// * `Ok(NacmConfig)` - Successfully parsed configuration
    /// * `Err(Box<dyn Error>)` - Parsing failed (malformed XML, unknown values, etc.)
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use nacm_validator::NacmConfig;
    /// 
    /// let xml = r#"
    /// <config xmlns="http://tail-f.com/ns/config/1.0">
    ///   <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
    ///     <enable-nacm>true</enable-nacm>
    ///     <read-default>deny</read-default>
    ///     <write-default>deny</write-default>
    ///     <exec-default>deny</exec-default>
    ///     <groups>
    ///       <group>
    ///         <name>admin</name>
    ///         <user-name>alice</user-name>
    ///       </group>
    ///     </groups>
    ///     <rule-list>
    ///       <name>admin-rules</name>
    ///       <group>admin</group>
    ///     </rule-list>
    ///   </nacm>
    /// </config>
    /// "#;
    /// 
    /// let config = NacmConfig::from_xml(xml).unwrap();
    /// assert_eq!(config.enable_nacm, true);
    /// ```
    pub fn from_xml(xml_content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Step 1: Parse XML into intermediate structures
        // serde_xml_rs automatically deserializes the XML based on our struct definitions
        let xml_config: XmlConfig = serde_xml_rs::from_str(xml_content)?;
        
        // Step 2: Convert XML groups to our internal representation
        // Transform from XML format to HashMap for efficient lookups
        let mut groups = HashMap::new();
        for xml_group in xml_config.nacm.groups.group {
            // Create internal group representation and add to HashMap for O(1) lookup
            groups.insert(xml_group.name.clone(), NacmGroup {
                name: xml_group.name,
                users: xml_group.user_names,
                gid: xml_group.gid, // Tail-f extension
            });
        }
        
        // Step 3: Convert XML rule lists to our internal representation
        // Process each rule list and assign ordering for rule precedence
        let mut rule_lists = Vec::new();
        for (order_base, xml_rule_list) in xml_config.nacm.rule_lists.iter().enumerate() {
            let mut rules = Vec::new();
            
            // Process each rule within this rule list
            for (rule_order, xml_rule) in xml_rule_list.rule.iter().enumerate() {
                // Step 3a: Parse access operations from string format
                // Handle both wildcard ("*") and space-separated operation lists
                let mut access_operations = HashSet::new();
                if let Some(ops_str) = &xml_rule.access_operations {
                    if ops_str.trim() == "*" {
                        // Wildcard means all operations
                        access_operations.insert(Operation::Read);
                        access_operations.insert(Operation::Create);
                        access_operations.insert(Operation::Update);
                        access_operations.insert(Operation::Delete);
                        access_operations.insert(Operation::Exec);
                    } else {
                        // Parse space-separated operation names like "read write"
                        for op in ops_str.split_whitespace() {
                            if let Ok(operation) = op.parse::<Operation>() {
                                access_operations.insert(operation);
                            }
                            // Note: Invalid operations are silently ignored
                        }
                    }
                }
                
                // Step 3b: Parse the rule effect (permit/deny)
                let effect = xml_rule.action.parse::<RuleEffect>()?;
                
                // Step 3c: Create internal rule representation
                // Calculate rule order: rule list order * 1000 + rule position
                // This ensures rules in earlier rule lists have higher priority
                rules.push(NacmRule {
                    name: xml_rule.name.clone(),
                    module_name: xml_rule.module_name.clone(),
                    rpc_name: xml_rule.rpc_name.clone(),
                    path: xml_rule.path.clone(),
                    access_operations,
                    effect,
                    // Calculate rule priority: list_position * 1000 + rule_position
                    // This ensures proper ordering across multiple rule lists
                    order: (order_base * 1000 + rule_order) as u32,
                    context: xml_rule.context.clone(), // Tail-f extension
                    log_if_permit: xml_rule.log_if_permit.is_some(), // Tail-f extension
                    log_if_deny: xml_rule.log_if_deny.is_some(), // Tail-f extension
                });
            }
            
            // Process command rules within this rule list (Tail-f extension)
            let mut command_rules = Vec::new();
            for (cmd_rule_order, xml_cmd_rule) in xml_rule_list.cmdrule.iter().enumerate() {
                // Parse command access operations
                let mut cmd_access_operations = HashSet::new();
                if let Some(ops_str) = &xml_cmd_rule.access_operations {
                    if ops_str.trim() == "*" {
                        // For command rules, wildcard typically means read and exec
                        cmd_access_operations.insert(Operation::Read);
                        cmd_access_operations.insert(Operation::Exec);
                    } else {
                        // Parse space-separated operation names like "read exec"
                        for op in ops_str.split_whitespace() {
                            if let Ok(operation) = op.parse::<Operation>() {
                                cmd_access_operations.insert(operation);
                            }
                        }
                    }
                } else {
                    // Default to all command operations if not specified
                    cmd_access_operations.insert(Operation::Read);
                    cmd_access_operations.insert(Operation::Exec);
                }
                
                // Parse command rule effect
                let cmd_effect = xml_cmd_rule.action.parse::<RuleEffect>()?;
                
                // Create internal command rule representation
                command_rules.push(NacmCommandRule {
                    name: xml_cmd_rule.name.clone(),
                    context: xml_cmd_rule.context.clone(),
                    command: xml_cmd_rule.command.clone(),
                    access_operations: cmd_access_operations,
                    effect: cmd_effect,
                    order: (order_base * 1000 + cmd_rule_order) as u32,
                    log_if_permit: xml_cmd_rule.log_if_permit.is_some(),
                    log_if_deny: xml_cmd_rule.log_if_deny.is_some(),
                    comment: xml_cmd_rule.comment.clone(),
                });
            }
            
            // Step 3d: Create the rule list with its associated group
            // Note: XML format has single group per rule list, our internal format supports multiple
            rule_lists.push(NacmRuleList {
                name: xml_rule_list.name.clone(),
                groups: vec![xml_rule_list.group.clone()],  // Wrap single group in Vec
                rules,
                command_rules, // Tail-f extension
            });
        }
        
        // Step 4: Create the final configuration object
        // Parse default policies from strings and assemble everything
        Ok(NacmConfig {
            enable_nacm: xml_config.nacm.enable_nacm,
            // Parse default policy strings ("permit"/"deny") to enum values
            read_default: xml_config.nacm.read_default.parse()?,
            write_default: xml_config.nacm.write_default.parse()?,
            exec_default: xml_config.nacm.exec_default.parse()?,
            // Parse Tail-f command default policies
            cmd_read_default: xml_config.nacm.cmd_read_default.parse()?,
            cmd_exec_default: xml_config.nacm.cmd_exec_default.parse()?,
            // Parse Tail-f logging settings (empty elements become true if present)
            log_if_default_permit: xml_config.nacm.log_if_default_permit.is_some(),
            log_if_default_deny: xml_config.nacm.log_if_default_deny.is_some(),
            groups,
            rule_lists,
        })
    }
    
    /// Validate an access request against the NACM configuration
    /// 
    /// This is the main validation function that determines whether an access
    /// request should be permitted or denied based on the NACM rules, including
    /// command rules from the Tail-f ACM extensions.
    /// 
    /// # Algorithm
    /// 
    /// 1. If NACM is disabled globally, permit all access
    /// 2. Find all groups the user belongs to
    /// 3. If this is a command request, check command rules first
    /// 4. Otherwise, check standard NACM data access rules
    /// 5. Sort rules by precedence (order field)
    /// 6. Return the effect and logging info of the first matching rule
    /// 7. If no rules match, apply the appropriate default policy
    /// 
    /// # Arguments
    /// 
    /// * `req` - The access request to validate
    /// 
    /// # Returns
    /// 
    /// * `ValidationResult` - Contains the access decision and logging flag
    /// 
    /// # Examples
    /// 
    /// ```rust
    /// use nacm_validator::{NacmConfig, AccessRequest, Operation, RequestContext, ValidationResult, RuleEffect};
    /// 
    /// # let config = NacmConfig {
    /// #     enable_nacm: true,
    /// #     read_default: RuleEffect::Deny,
    /// #     write_default: RuleEffect::Deny,
    /// #     exec_default: RuleEffect::Deny,
    /// #     cmd_read_default: RuleEffect::Permit,
    /// #     cmd_exec_default: RuleEffect::Permit,
    /// #     log_if_default_permit: false,
    /// #     log_if_default_deny: false,
    /// #     groups: std::collections::HashMap::new(),
    /// #     rule_lists: vec![],
    /// # };
    /// let request = AccessRequest {
    ///     user: "alice",
    ///     module_name: Some("ietf-interfaces"),
    ///     rpc_name: None,
    ///     operation: Operation::Read,
    ///     path: Some("/interfaces"),
    ///     context: Some(&RequestContext::NETCONF),
    ///     command: None,
    /// };
    /// 
    /// let result = config.validate(&request);
    /// // Result contains both the access decision and logging flag
    /// ```
    pub fn validate(&self, req: &AccessRequest) -> ValidationResult {
        // Step 1: If NACM is disabled, permit all access without logging
        if !self.enable_nacm {
            return ValidationResult {
                effect: RuleEffect::Permit,
                should_log: false,
            };
        }
        
        // Step 2: Find all groups this user belongs to
        // Uses functional programming style with iterator chains
        let user_groups: Vec<&str> = self.groups
            .iter()                    // Iterator over (group_name, group) pairs
            .filter_map(|(group_name, group)| {  // Transform and filter in one step
                if group.users.contains(&req.user.to_string()) {
                    Some(group_name.as_str())  // Include this group name
                } else {
                    None                       // Skip this group
                }
            })
            .collect();                // Collect into a Vec
        
        // Step 3: Check if this is a command request
        if req.command.is_some() {
            return self.validate_command_request(req, &user_groups);
        }
        
        // Step 4: Standard NACM data access validation
        self.validate_data_request(req, &user_groups)
    }
    
    /// Validate a command access request (Tail-f ACM extension)
    /// 
    /// This helper function specifically handles command rule validation
    /// for CLI, WebUI, and other command-based access requests.
    /// 
    /// # Arguments
    /// 
    /// * `req` - The access request containing command information
    /// * `user_groups` - List of groups the user belongs to
    /// 
    /// # Returns
    /// 
    /// * `ValidationResult` - Contains the access decision and logging flag
    fn validate_command_request(&self, req: &AccessRequest, user_groups: &[&str]) -> ValidationResult {
        let mut matching_cmd_rules = Vec::new();
        
        // Collect all matching command rules from applicable rule lists
        for rule_list in &self.rule_lists {
            // Check if this rule list applies to any of the user's groups
            let applies = rule_list.groups.iter().any(|group| {
                group == "*" || user_groups.contains(&group.as_str())
            });
            
            if applies {
                // Check each command rule in this rule list
                for cmd_rule in &rule_list.command_rules {
                    if self.command_rule_matches(cmd_rule, req) {
                        matching_cmd_rules.push(cmd_rule);
                    }
                }
            }
        }
        
        // Sort command rules by precedence (lower order = higher priority)
        matching_cmd_rules.sort_by_key(|r| r.order);
        
        // Return the effect of the first matching command rule
        if let Some(cmd_rule) = matching_cmd_rules.first() {
            let should_log = match cmd_rule.effect {
                RuleEffect::Permit => cmd_rule.log_if_permit,
                RuleEffect::Deny => cmd_rule.log_if_deny,
            };
            
            ValidationResult {
                effect: cmd_rule.effect,
                should_log,
            }
        } else {
            // No command rules matched - apply command default policy
            let default_effect = match req.operation {
                Operation::Read => self.cmd_read_default,
                _ => self.cmd_exec_default, // All other operations default to exec policy
            };
            
            let should_log = match default_effect {
                RuleEffect::Permit => self.log_if_default_permit,
                RuleEffect::Deny => self.log_if_default_deny,
            };
            
            ValidationResult {
                effect: default_effect,
                should_log,
            }
        }
    }
    
    /// Validate a data access request (standard NACM)
    /// 
    /// This helper function handles standard NACM data access rule validation
    /// for NETCONF and similar protocol-based requests.
    /// 
    /// # Arguments
    /// 
    /// * `req` - The access request containing data access information
    /// * `user_groups` - List of groups the user belongs to
    /// 
    /// # Returns
    /// 
    /// * `ValidationResult` - Contains the access decision and logging flag
    fn validate_data_request(&self, req: &AccessRequest, user_groups: &[&str]) -> ValidationResult {
        let mut matching_rules = Vec::new();
        
        // Collect all matching rules from applicable rule lists
        for rule_list in &self.rule_lists {
            // Check if this rule list applies to any of the user's groups
            let applies = rule_list.groups.iter().any(|group| {
                group == "*" || user_groups.contains(&group.as_str())
            });
            
            if applies {
                // Check each rule in this rule list
                for rule in &rule_list.rules {
                    if self.rule_matches(rule, req) {
                        matching_rules.push(rule);
                    }
                }
            }
        }
        
        // Sort rules by precedence (lower order = higher priority)
        matching_rules.sort_by_key(|r| r.order);
        
        // Return the effect of the first matching rule
        if let Some(rule) = matching_rules.first() {
            let should_log = match rule.effect {
                RuleEffect::Permit => rule.log_if_permit,
                RuleEffect::Deny => rule.log_if_deny,
            };
            
            ValidationResult {
                effect: rule.effect,
                should_log,
            }
        } else {
            // No rules matched - apply default policy based on operation type
            let default_effect = match req.operation {
                Operation::Read => self.read_default,
                // Group write operations together (create/update/delete)
                Operation::Create | Operation::Update | Operation::Delete => self.write_default,
                Operation::Exec => self.exec_default,
            };
            
            let should_log = match default_effect {
                RuleEffect::Permit => self.log_if_default_permit,
                RuleEffect::Deny => self.log_if_default_deny,
            };
            
            ValidationResult {
                effect: default_effect,
                should_log,
            }
        }
    }
    
    /// Check if a command rule matches an access request (Tail-f ACM extension)
    /// 
    /// This private helper function determines whether a specific command rule
    /// applies to a given access request. A command rule matches if ALL of its
    /// conditions are satisfied (AND logic).
    /// 
    /// # Matching Logic
    /// 
    /// * **Operations**: Rule must cover the requested operation
    /// * **Context**: Rule's context must match the request context (or be wildcard)
    /// * **Command**: Rule's command pattern must match the requested command
    /// 
    /// # Arguments
    /// 
    /// * `cmd_rule` - The command rule to check
    /// * `req` - The access request to match against
    /// 
    /// # Returns
    /// 
    /// * `true` if the command rule matches the request
    /// * `false` if any condition fails
    fn command_rule_matches(&self, cmd_rule: &NacmCommandRule, req: &AccessRequest) -> bool {
        // Check 1: Operations - Rule must cover the requested operation
        if !cmd_rule.access_operations.is_empty() && !cmd_rule.access_operations.contains(&req.operation) {
            return false;
        }
        
        // Check 2: Context matching
        if let Some(rule_context) = &cmd_rule.context {
            if let Some(req_context) = req.context {
                if !req_context.matches(rule_context) {
                    return false;
                }
            } else if rule_context != "*" {
                // Rule specifies context but request has none
                return false;
            }
        }
        
        // Check 3: Command matching
        if let Some(rule_command) = &cmd_rule.command {
            if let Some(req_command) = req.command {
                if !self.command_matches(rule_command, req_command) {
                    return false;
                }
            } else if rule_command != "*" {
                // Rule specifies command but request has none
                return false;
            }
        }
        
        true
    }
    
    /// Check if a command pattern matches a requested command
    /// 
    /// Implements command matching logic supporting:
    /// - Exact string matching
    /// - Wildcard matching with '*'
    /// - Prefix matching for command hierarchies
    /// 
    /// # Arguments
    /// 
    /// * `pattern` - The command pattern from the rule
    /// * `command` - The requested command
    /// 
    /// # Returns
    /// 
    /// * `true` if the pattern matches the command
    /// * `false` otherwise
    fn command_matches(&self, pattern: &str, command: &str) -> bool {
        if pattern == "*" {
            return true; // Wildcard matches everything
        }
        
        if pattern == command {
            return true; // Exact match
        }
        
        // Check for wildcard suffix (e.g., "show *")
        if let Some(stripped) = pattern.strip_suffix('*') {
            let prefix = &stripped.trim();
            return command.starts_with(prefix);
        }
        
        false
    }
    
    
    /// Check if a rule matches an access request
    /// 
    /// This private helper function determines whether a specific rule
    /// applies to a given access request. A rule matches if ALL of its
    /// conditions are satisfied (AND logic).
    /// 
    /// # Matching Logic
    /// 
    /// * **Operations**: Rule must cover the requested operation
    /// * **Module**: Rule's module must match (or be unspecified)
    /// * **RPC**: Rule's RPC must match (or be wildcard/unspecified)
    /// * **Path**: Rule's path must match (with wildcard support)
    /// 
    /// # Arguments
    /// 
    /// * `rule` - The rule to check
    /// * `req` - The access request to match against
    /// 
    /// # Returns
    /// 
    /// * `true` if the rule matches the request
    /// * `false` if any condition fails
    fn rule_matches(&self, rule: &NacmRule, req: &AccessRequest) -> bool {
        // Check 1: Operations - Rule must cover the requested operation
        // If rule specifies operations, the request operation must be included
        if !rule.access_operations.is_empty() && !rule.access_operations.contains(&req.operation) {
            return false;  // Rule doesn't cover this operation
        }
        
        // Check 2: Context matching (Tail-f extension)
        if let Some(rule_context) = &rule.context {
            if let Some(req_context) = req.context {
                if !req_context.matches(rule_context) {
                    return false;  // Context doesn't match
                }
            } else if rule_context != "*" {
                // Rule specifies context but request has none
                return false;
            }
        }
        
        // Check 3: Module name matching
        // If rule specifies a module, request must be for the same module
        if let Some(rule_module) = &rule.module_name {
            if let Some(req_module) = req.module_name {
                if rule_module != req_module {
                    return false;  // Different modules
                }
            } else {
                return false;  // Rule requires module, but request has none
            }
        }
        
        // Check 4: RPC name matching
        // Special handling for wildcard ("*") RPCs
        if let Some(rule_rpc) = &rule.rpc_name {
            if rule_rpc == "*" {
                // Wildcard matches any RPC (or no RPC)
            } else if let Some(req_rpc) = req.rpc_name {
                if rule_rpc != req_rpc {
                    return false;  // Different RPC names
                }
            } else {
                return false;  // Rule requires specific RPC, but request has none
            }
        }
        
        // Check 5: Path matching (simplified XPath-style matching)
        // Supports exact matches and simple wildcard patterns
        if let Some(rule_path) = &rule.path {
            if rule_path == "/" {
                // Root path matches everything (universal path rule)
            } else if let Some(req_path) = req.path {
                if rule_path.ends_with("/*") {
                    // Wildcard path: "/interfaces/*" matches "/interfaces/interface[1]"
                    let prefix = &rule_path[..rule_path.len() - 2];
                    if !req_path.starts_with(prefix) {
                        return false;  // Path doesn't match prefix
                    }
                } else if rule_path != req_path {
                    return false;  // Exact path mismatch
                }
            } else {
                return false;  // Rule requires path, but request has none
            }
        }
        
        // All checks passed - rule matches this request
        true
    }
}

// --- Example usage and tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_parsing() {
        let xml = r#"
        <config xmlns="http://tail-f.com/ns/config/1.0">
            <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
                <enable-nacm>true</enable-nacm>
                <read-default>deny</read-default>
                <write-default>deny</write-default>
                <exec-default>deny</exec-default>
                <groups>
                    <group>
                        <name>admin</name>
                        <user-name>admin</user-name>
                    </group>
                </groups>
                <rule-list>
                    <name>admin</name>
                    <group>admin</group>
                    <rule>
                        <name>any-rpc</name>
                        <rpc-name>*</rpc-name>
                        <access-operations>exec</access-operations>
                        <action>permit</action>
                    </rule>
                </rule-list>
            </nacm>
        </config>"#;
        
        let config = NacmConfig::from_xml(xml).unwrap();
        assert!(config.enable_nacm);
        assert_eq!(config.read_default, RuleEffect::Deny);
        assert_eq!(config.groups.len(), 1);
        assert_eq!(config.rule_lists.len(), 1);
    }

    #[test]
    fn test_nacm_validation_admin() {
        let xml = r#"
        <config xmlns="http://tail-f.com/ns/config/1.0">
            <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
                <enable-nacm>true</enable-nacm>
                <read-default>deny</read-default>
                <write-default>deny</write-default>
                <exec-default>deny</exec-default>
                <groups>
                    <group>
                        <name>admin</name>
                        <user-name>admin</user-name>
                    </group>
                </groups>
                <rule-list>
                    <name>admin</name>
                    <group>admin</group>
                    <rule>
                        <name>any-rpc</name>
                        <rpc-name>*</rpc-name>
                        <access-operations>exec</access-operations>
                        <action>permit</action>
                    </rule>
                </rule-list>
            </nacm>
        </config>"#;
        
        let config = NacmConfig::from_xml(xml).unwrap();
        
        let req = AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
            context: Some(&RequestContext::NETCONF),
            command: None,
        };
        
        let result = config.validate(&req);
        assert_eq!(result.effect, RuleEffect::Permit);
    }

    #[test]
    fn test_real_nacm_xml() {
        use std::path::Path;
        
        let xml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("data")
            .join("aaa_ncm_init.xml");
            
        let xml = std::fs::read_to_string(&xml_path)
            .unwrap_or_else(|_| panic!("Failed to read XML file at {:?}", xml_path));
        
        let config = NacmConfig::from_xml(&xml).expect("Failed to parse XML");
        
        // Test admin user - should be able to execute any RPC
        let admin_req = AccessRequest {
            user: "admin",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
            context: Some(&RequestContext::NETCONF),
            command: None,
        };
        let admin_result = config.validate(&admin_req);
        assert_eq!(admin_result.effect, RuleEffect::Permit);
        
        // Test oper user - should be denied edit-config
        let oper_req = AccessRequest {
            user: "oper",
            module_name: None,
            rpc_name: Some("edit-config"),
            operation: Operation::Exec,
            path: None,
            context: Some(&RequestContext::NETCONF),
            command: None,
        };
        let oper_result = config.validate(&oper_req);
        assert_eq!(oper_result.effect, RuleEffect::Deny);
        
        // Test oper user - should be denied writing to nacm module
        let nacm_write_req = AccessRequest {
            user: "oper",
            module_name: Some("ietf-netconf-acm"),
            rpc_name: None,
            operation: Operation::Update,
            path: Some("/"),
            context: Some(&RequestContext::NETCONF),
            command: None,
        };
        let nacm_write_result = config.validate(&nacm_write_req);
        assert_eq!(nacm_write_result.effect, RuleEffect::Deny);
        
        // Test any user with example module - should be permitted for /misc/*
        let example_req = AccessRequest {
            user: "Guest",
            module_name: Some("example"),
            rpc_name: None,
            operation: Operation::Read,
            path: Some("/misc/foo"),
            context: Some(&RequestContext::NETCONF),
            command: None,
        };
        let example_result = config.validate(&example_req);
        assert_eq!(example_result.effect, RuleEffect::Permit);
        
        // Test configuration loaded properly
        assert!(config.enable_nacm);
        assert_eq!(config.read_default, RuleEffect::Deny);
        assert_eq!(config.write_default, RuleEffect::Deny);
        assert_eq!(config.exec_default, RuleEffect::Deny);
        
        // Check groups
        assert_eq!(config.groups.len(), 2);
        assert!(config.groups.contains_key("admin"));
        assert!(config.groups.contains_key("oper"));
        
        let admin_group = &config.groups["admin"];
        assert_eq!(admin_group.users, vec!["admin", "private"]);
        
        let oper_group = &config.groups["oper"];
        assert_eq!(oper_group.users, vec!["oper", "public"]);
        
        // Check rule lists
        assert_eq!(config.rule_lists.len(), 3);
        
        println!("Successfully parsed {} groups and {} rule lists", 
                 config.groups.len(), config.rule_lists.len());
    }
    
    #[test]
    fn test_tailf_command_rules() {
        let xml = r#"
        <config xmlns="http://tail-f.com/ns/config/1.0">
            <nacm xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm">
                <enable-nacm>true</enable-nacm>
                <read-default>deny</read-default>
                <write-default>deny</write-default>
                <exec-default>deny</exec-default>
                <cmd-read-default xmlns="http://tail-f.com/yang/acm">deny</cmd-read-default>
                <cmd-exec-default xmlns="http://tail-f.com/yang/acm">deny</cmd-exec-default>
                <log-if-default-permit xmlns="http://tail-f.com/yang/acm"/>
                <log-if-default-deny xmlns="http://tail-f.com/yang/acm"/>
                <groups>
                    <group>
                        <name>operators</name>
                        <user-name>oper</user-name>
                        <gid xmlns="http://tail-f.com/yang/acm">1000</gid>
                    </group>
                </groups>
                <rule-list>
                    <name>operators</name>
                    <group>operators</group>
                    <cmdrule xmlns="http://tail-f.com/yang/acm">
                        <name>cli-show-status</name>
                        <context>cli</context>
                        <command>show status</command>
                        <access-operations>read exec</access-operations>
                        <action>permit</action>
                        <log-if-permit/>
                    </cmdrule>
                    <cmdrule xmlns="http://tail-f.com/yang/acm">
                        <name>cli-help</name>
                        <context>cli</context>
                        <command>help</command>
                        <action>permit</action>
                    </cmdrule>
                    <cmdrule xmlns="http://tail-f.com/yang/acm">
                        <name>deny-reboot</name>
                        <context>*</context>
                        <command>reboot</command>
                        <action>deny</action>
                        <log-if-deny/>
                    </cmdrule>
                </rule-list>
            </nacm>
        </config>"#;
        
        let config = NacmConfig::from_xml(xml).unwrap();
        
        // Test Tail-f extensions parsed correctly
        assert_eq!(config.cmd_read_default, RuleEffect::Deny);
        assert_eq!(config.cmd_exec_default, RuleEffect::Deny);
        assert!(config.log_if_default_permit);
        assert!(config.log_if_default_deny);
        
        // Test group GID
        let oper_group = &config.groups["operators"];
        assert_eq!(oper_group.gid, Some(1000));
        
        // Test command rule parsed correctly
        let rule_list = &config.rule_lists[0];
        assert_eq!(rule_list.command_rules.len(), 3);
        
        let show_status_rule = &rule_list.command_rules[0];
        assert_eq!(show_status_rule.name, "cli-show-status");
        assert_eq!(show_status_rule.context.as_deref(), Some("cli"));
        assert_eq!(show_status_rule.command.as_deref(), Some("show status"));
        assert_eq!(show_status_rule.effect, RuleEffect::Permit);
        assert!(show_status_rule.log_if_permit);
        assert!(!show_status_rule.log_if_deny);
        
        // Test CLI command validation - should permit
        let cli_show_req = AccessRequest {
            user: "oper",
            module_name: None,
            rpc_name: None,
            operation: Operation::Read,
            path: None,
            context: Some(&RequestContext::CLI),
            command: Some("show status"),
        };
        let show_result = config.validate(&cli_show_req);
        assert_eq!(show_result.effect, RuleEffect::Permit);
        assert!(show_result.should_log); // Should log because rule has log-if-permit
        
        // Test CLI help command - should permit but not log
        let cli_help_req = AccessRequest {
            user: "oper",
            module_name: None,
            rpc_name: None,
            operation: Operation::Exec,
            path: None,
            context: Some(&RequestContext::CLI),
            command: Some("help"),
        };
        let help_result = config.validate(&cli_help_req);
        assert_eq!(help_result.effect, RuleEffect::Permit);
        assert!(!help_result.should_log); // No logging flags set
        
        // Test reboot command from any context - should deny and log
        let reboot_req = AccessRequest {
            user: "oper",
            module_name: None,
            rpc_name: None,
            operation: Operation::Exec,
            path: None,
            context: Some(&RequestContext::WebUI),
            command: Some("reboot"),
        };
        let reboot_result = config.validate(&reboot_req);
        assert_eq!(reboot_result.effect, RuleEffect::Deny);
        assert!(reboot_result.should_log); // Should log because rule has log-if-deny
        
        // Test command that doesn't match any rule - should use default and log
        let unknown_cmd_req = AccessRequest {
            user: "oper",
            module_name: None,
            rpc_name: None,
            operation: Operation::Exec,
            path: None,
            context: Some(&RequestContext::CLI),
            command: Some("unknown-command"),
        };
        let unknown_result = config.validate(&unknown_cmd_req);
        assert_eq!(unknown_result.effect, RuleEffect::Deny); // cmd-exec-default is deny
        assert!(unknown_result.should_log); // log-if-default-deny is true
    }
}