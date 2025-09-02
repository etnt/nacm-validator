//! # NACM Validator CLI Tool
//! 
//! A command-line interface for validating access requests against NACM (Network Access Control Model) configurations
//! with support for both single files and multiple configuration files using YANG merge semantics.
//! 
//! This binary provides a convenient way to:
//! - Validate single access requests with exit code feedback for shell scripts
//! - Process batch requests from JSON input  
//! - Load and merge multiple configuration files from a directory
//! - Apply YANG merge semantics for modular configuration management
//! - Output results in multiple formats (text, JSON, exit-code only)
//! - Integrate NACM validation into automation pipelines
//! 
//! ## Configuration Options
//! 
//! ### Single Configuration File (Traditional)
//! Use `--config FILE` to load a single XML configuration file:
//! 
//! ```bash
//! nacm-validator --config /path/to/config.xml --user alice --operation read
//! ```
//! 
//! ### Multiple Configuration Files (v0.2.0+)
//! Use `--config-dir DIR` to load and merge all XML files from a directory using YANG merge semantics:
//! 
//! ```bash
//! # Load all .xml files from directory, process alphabetically
//! nacm-validator --config-dir /etc/nacm/configs.d --user alice --operation read --verbose
//! 
//! # Files processed in order: 01-base.xml, 02-groups.xml, 03-rules.xml
//! # YANG merge: globals use last-wins, groups/rules are additive
//! # Invalid files are skipped with warnings, processing continues
//! ```
//! 
//! **YANG Merge Semantics:**
//! - **Global settings** (enable-nacm, defaults): Last file wins  
//! - **Groups and rules**: Merged additively across files
//! - **Rule precedence**: Maintained with automatic ordering
//! - **Error resilience**: Invalid files skipped, valid ones processed
//! 
//! ## Usage Examples
//! 
//! ### Single Request Validation
//! ```bash
//! # Basic validation with single config
//! nacm-validator --config config.xml --user alice --operation read --module ietf-interfaces
//! 
//! # Multiple configs with verbose output showing merge process
//! nacm-validator --config-dir /etc/nacm --user alice --operation read --verbose
//! 
//! # JSON output for programmatic processing
//! nacm-validator --config config.xml --user bob --operation exec --rpc edit-config --format json
//! 
//! # Exit code only for shell scripting
//! if nacm-validator --config-dir /etc/nacm --user charlie --operation create --format exit-code; then
//!     echo "Access granted"
//! fi
//! ```
//! 
//! ### Batch Processing
//! ```bash
//! # Process multiple requests from JSON with merged configurations
//! echo '{"user":"alice","operation":"read","module":"ietf-interfaces"}' | \
//!   nacm-validator --config-dir /etc/nacm --json-input
//! 
//! # Batch processing with single config (traditional)  
//! cat requests.json | nacm-validator --config config.xml --json-input
//! ```
//! 
//! ### Integration Examples
//! ```bash
//! # Validate configuration merge before deployment
//! nacm-validator --config-dir ./staging-configs --user test-user --operation read --verbose
//! 
//! # Shell script integration with error handling
//! if ! nacm-validator --config-dir /etc/nacm --user "$USER" --operation "$OP" --format exit-code; then
//!     echo "Access denied for $USER to perform $OP" >&2
//!     exit 1
//! fi
//! ```
//! 
//! ## Exit Codes
//! 
//! - **0**: Access permitted
//! - **1**: Access denied  
//! - **2**: Error (invalid config, missing file, etc.)

use clap::{Args, Parser, ValueEnum};
use nacm_validator::{AccessRequest, NacmConfig, Operation, RuleEffect, RequestContext};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process;

/// Command-line interface structure for the NACM validator
/// 
/// This struct defines all the command-line arguments and options.
/// The `#[derive(Parser)]` attribute generates the argument parsing code automatically
/// using the `clap` crate, which is Rust's standard CLI argument parser.
/// 
/// ## Field Details
/// 
/// Fields are made `Option<T>` when they're not required in all modes.
/// For example, `--user` and `--operation` are required for single request mode
/// but not needed when using `--json-input` for batch processing.
#[derive(Parser)]
#[command(author, version, about = "NACM Access Control Validator", long_about = None)]
struct Cli {
    /// Configuration source - either a file or directory
    #[command(flatten)]
    config_source: ConfigSource,

    /// Username making the request
    /// 
    /// Optional because it's not needed in JSON input mode where the username
    /// comes from the JSON payload instead.
    #[arg(short, long)]
    user: Option<String>,

    /// Module name (optional)
    /// 
    /// YANG module name that the access request pertains to.
    /// If not specified, the request is not module-specific.
    #[arg(short, long)]
    module: Option<String>,

    /// RPC name (optional)
    /// 
    /// Name of the RPC being called. Use "*" for wildcard matching.
    /// If not specified, the request is not RPC-specific.
    #[arg(short, long)]
    rpc: Option<String>,

    /// Operation type
    /// 
    /// The type of operation being performed. Optional in JSON mode
    /// where it comes from the JSON payload.
    #[arg(short, long)]
    operation: Option<OperationArg>,

    /// Path (optional)
    /// 
    /// XPath or data path for the access request.
    /// Supports simple wildcard patterns like "/interfaces/*".
    #[arg(short, long)]
    path: Option<String>,

    /// Request context (optional)
    /// 
    /// The management interface or context from which the request originates.
    /// Used for Tail-f ACM context-aware access control.
    #[arg(short = 'x', long)]
    context: Option<ContextArg>,

    /// Command (optional)
    /// 
    /// Command being executed (for command-based access control).
    /// Used with Tail-f ACM command rules for CLI and WebUI access.
    #[arg(short = 'C', long)]
    command: Option<String>,

    /// Output format
    /// 
    /// Controls how results are displayed:
    /// - `text`: Human-readable output (default)
    /// - `json`: Structured JSON for programmatic processing
    /// - `exit-code`: No output, only exit codes (for shell scripting)
    #[arg(long, default_value = "text")]
    format: OutputFormat,

    /// Verbose output
    /// 
    /// Shows additional information like configuration summary,
    /// rule matching details, and group membership.
    #[arg(short, long)]
    verbose: bool,

    /// JSON input mode - read request from stdin
    /// 
    /// When enabled, the tool reads JSON-formatted requests from standard input
    /// instead of using command-line arguments. Useful for batch processing.
    #[arg(long)]
    json_input: bool,
}

/// Configuration source options
/// 
/// This struct groups the mutually exclusive configuration source options.
/// Users must specify either a single file or a directory containing multiple files.
#[derive(Args)]
#[group(required = true, multiple = false)]
struct ConfigSource {
    /// Path to the NACM XML configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path to directory containing NACM XML configuration files
    #[arg(long)]
    config_dir: Option<PathBuf>,
}

/// Command-line operation argument wrapper
/// 
/// This enum wraps our library's `Operation` enum to work with clap's
/// argument parsing. The `#[derive(ValueEnum)]` allows clap to automatically
/// generate help text and validate command-line values.
/// 
/// We need this wrapper because we can't add clap derives to the library types
/// (that would make the library depend on clap, which CLI users might not want).
#[derive(Clone, ValueEnum)]
enum OperationArg {
    /// Reading or retrieving data
    Read,
    /// Creating new data  
    Create,
    /// Modifying existing data
    Update,
    /// Removing data
    Delete,
    /// Executing RPCs or actions
    Exec,
}

/// Convert CLI operation argument to library operation type
/// 
/// This `From` trait implementation allows automatic conversion between
/// the CLI enum and the library enum. Rust's type system ensures this
/// conversion is always safe and never fails.
impl From<OperationArg> for Operation {
    fn from(op: OperationArg) -> Self {
        match op {
            OperationArg::Read => Operation::Read,
            OperationArg::Create => Operation::Create,
            OperationArg::Update => Operation::Update,
            OperationArg::Delete => Operation::Delete,
            OperationArg::Exec => Operation::Exec,
        }
    }
}

/// Command-line context argument wrapper
/// 
/// This enum wraps our library's `RequestContext` enum to work with clap's
/// argument parsing. Similar to `OperationArg`, this allows CLI parsing
/// without making the library depend on clap.
#[derive(Clone, ValueEnum)]
enum ContextArg {
    /// NETCONF protocol access
    Netconf,
    /// Command-line interface access
    Cli,
    /// Web-based user interface access
    Webui,
}

/// Convert CLI context argument to library context type
/// 
/// This `From` trait implementation allows automatic conversion between
/// the CLI enum and the library enum.
impl From<ContextArg> for nacm_validator::RequestContext {
    fn from(ctx: ContextArg) -> Self {
        match ctx {
            ContextArg::Netconf => nacm_validator::RequestContext::NETCONF,
            ContextArg::Cli => nacm_validator::RequestContext::CLI,
            ContextArg::Webui => nacm_validator::RequestContext::WebUI,
        }
    }
}

/// Output format options for results
/// 
/// Controls how validation results are displayed to the user.
/// Each format serves different use cases and integration scenarios.
#[derive(Clone, ValueEnum)]
enum OutputFormat {
    /// Human-readable text output (default)
    /// Shows "PERMIT" or "DENY" with optional verbose details
    Text,
    /// Structured JSON output for programmatic processing
    /// Includes all request details and decision information  
    Json,
    /// Exit code only, no text output
    /// Perfect for shell scripting where you only care about success/failure
    ExitCode,
}

/// JSON request structure for batch processing
/// 
/// When using `--json-input` mode, requests are provided as JSON objects
/// with this structure. All fields are deserialized from the JSON payload.
/// 
/// Example JSON:
/// ```json
/// {
///   "user": "alice",
///   "module": "ietf-interfaces", 
///   "operation": "read",
///   "path": "/interfaces/interface[name='eth0']",
///   "context": "netconf",
///   "command": "show status"
/// }
/// ```
#[derive(Serialize, Deserialize)]
struct JsonRequest {
    /// Username making the request
    user: String,
    /// YANG module name (optional)
    module: Option<String>,
    /// RPC name (optional) 
    rpc: Option<String>,
    /// Operation type as string ("read", "create", etc.)
    operation: String,
    /// XPath or data path (optional)
    path: Option<String>,
    /// Request context as string ("netconf", "cli", "webui") (optional)
    context: Option<String>,
    /// Command being executed (optional)
    command: Option<String>,
}

/// JSON response structure for results
/// 
/// Used when outputting results in JSON format. Includes both the
/// access decision and all the request details for complete traceability.
#[derive(Serialize)]
struct JsonResult {
    /// Access decision: "permit" or "deny"
    decision: String,
    /// Original request details echoed back
    user: String,
    module: Option<String>,
    rpc: Option<String>,
    operation: String,
    path: Option<String>,
    /// Request context ("netconf", "cli", "webui")
    context: Option<String>,
    /// Command being executed
    command: Option<String>,
    /// Indicates whether the configuration was loaded successfully
    config_loaded: bool,
    /// Whether this decision should be logged (Tail-f ACM extension)
    should_log: bool,
}

/// Main entry point for the NACM validator CLI tool
/// 
/// This function orchestrates the entire validation process:
/// 1. Parse command-line arguments using clap
/// 2. Load and validate the NACM configuration file
/// 3. Route to appropriate handler based on input mode
/// 4. Set proper exit codes for shell script integration
/// 
/// ## Error Handling
/// 
/// The function uses Rust's standard error handling patterns:
/// - `Result<T, E>` for operations that can fail
/// - `process::exit()` with specific codes for different error types
/// - Graceful error messages to stderr
/// 
/// ## Exit Codes
/// - 0: Access permitted (success)
/// - 1: Access denied 
/// - 2: Configuration or runtime error
fn main() {
    // Parse command-line arguments
    // If parsing fails (invalid args), clap automatically shows help and exits
    let cli = Cli::parse();

    // Load NACM configuration from the specified source
    let config = match load_configs(&cli) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            process::exit(2);  // Exit with error code 2 for configuration issues
        }
    };

    // Show configuration summary if verbose mode is enabled
    if cli.verbose {
        match (&cli.config_source.config, &cli.config_source.config_dir) {
            (Some(file), None) => eprintln!("Loaded NACM config from file: {:?}", file),
            (None, Some(dir)) => eprintln!("Loaded NACM config from directory: {:?}", dir),
            _ => unreachable!("clap ensures one option is present"),
        }
        eprintln!("NACM enabled: {}", config.enable_nacm);
        eprintln!("Groups: {}", config.groups.len());
        eprintln!("Rule lists: {}", config.rule_lists.len());
    }

    // Route to appropriate handler based on input mode
    if cli.json_input {
        // Batch processing mode: read JSON requests from stdin
        handle_json_input(&config, &cli);
    } else {
        // Single request mode: use command-line arguments
        
        // Validate required arguments for single request mode
        // In JSON mode, these come from the JSON payload instead
        let user = match &cli.user {
            Some(u) => u,
            None => {
                eprintln!("Error: --user is required for single request mode");
                process::exit(2);
            }
        };
        let operation = match &cli.operation {
            Some(op) => op,
            None => {
                eprintln!("Error: --operation is required for single request mode");
                process::exit(2);
            }
        };
        
        // Process the single request and exit with appropriate code
        handle_single_request(&config, &cli, user, operation);
    }
}

/// Load and parse NACM configuration from either file or directory
/// 
/// This function dispatches to the appropriate loading function based on
/// the configuration source specified in the CLI arguments.
/// 
/// ## Parameters
/// 
/// * `cli` - Parsed command-line arguments
/// 
/// ## Returns
/// 
/// * `Ok(NacmConfig)` - Successfully loaded and parsed configuration
/// * `Err(Box<dyn Error>)` - Configuration loading failed
fn load_configs(cli: &Cli) -> Result<NacmConfig, Box<dyn std::error::Error>> {
    match &cli.config_source {
        ConfigSource { config: Some(file), .. } => {
            if cli.verbose {
                eprintln!("Loading single config file: {:?}", file);
            }
            load_single_config(file)
        },
        ConfigSource { config_dir: Some(dir), .. } => {
            if cli.verbose {
                eprintln!("Loading config directory: {:?}", dir);
            }
            load_directory_configs(dir, cli.verbose)
        },
        _ => unreachable!("clap ensures one option is present"),
    }
}

/// Load and parse NACM configuration from directory
/// 
/// This function discovers XML files in the specified directory, loads and
/// parses each one, then merges them according to YANG merge semantics.
/// 
/// ## Parameters
/// 
/// * `dir` - Path to directory containing XML configuration files
/// * `verbose` - Whether to show detailed loading information
/// 
/// ## Returns
/// 
/// * `Ok(NacmConfig)` - Successfully merged configuration
/// * `Err(Box<dyn Error>)` - Directory loading or merging failed
fn load_directory_configs(dir: &PathBuf, verbose: bool) -> Result<NacmConfig, Box<dyn std::error::Error>> {
    // Validate directory exists
    if !dir.is_dir() {
        return Err(format!("Config directory does not exist: {:?}", dir).into());
    }

    // Discover XML files
    let xml_files = discover_xml_files(dir)?;
    
    if xml_files.is_empty() {
        eprintln!("Warning: No XML files found in directory {:?}", dir);
        return Ok(create_default_config());
    }

    if verbose {
        eprintln!("Found {} XML configuration files:", xml_files.len());
        for (idx, file) in xml_files.iter().enumerate() {
            eprintln!("  {}. {:?}", idx + 1, file.file_name().unwrap_or_default());
        }
    }

    // Load and parse each file
    let mut configs: Vec<(NacmConfig, usize)> = Vec::new();
    let mut errors = Vec::new();

    for (file_index, file_path) in xml_files.iter().enumerate() {
        match load_single_config(file_path) {
            Ok(config) => {
                if verbose {
                    eprintln!("✓ Successfully loaded: {:?}", file_path.file_name().unwrap_or_default());
                }
                configs.push((config, file_index));
            },
            Err(e) => {
                let error_msg = format!("Failed to load {:?}: {}", file_path.file_name().unwrap_or_default(), e);
                eprintln!("✗ {}", error_msg);
                errors.push(error_msg);
            }
        }
    }

    // Check if we have any valid configurations
    if configs.is_empty() {
        return Err(format!(
            "All {} configuration files failed to load:\n{}",
            xml_files.len(),
            errors.join("\n")
        ).into());
    }

    if !errors.is_empty() {
        eprintln!("Warning: {} out of {} files failed to load, continuing with {} valid configurations", 
                  errors.len(), xml_files.len(), configs.len());
    }

    // Merge configurations
    if verbose {
        eprintln!("Merging {} configurations...", configs.len());
    }
    
    let merged_config = NacmConfig::merge(configs)?;
    
    if verbose {
        eprintln!("✓ Configuration merge completed");
        eprintln!("  - {} groups loaded", merged_config.groups.len());
        eprintln!("  - {} rule lists loaded", merged_config.rule_lists.len());
        let total_rules: usize = merged_config.rule_lists.iter()
            .map(|rl| rl.rules.len() + rl.command_rules.len())
            .sum();
        eprintln!("  - {} total rules loaded", total_rules);
    }

    Ok(merged_config)
}

/// Discover XML files in a directory
/// 
/// This function scans the specified directory for valid XML configuration files,
/// applying filtering rules to exclude hidden, backup, and temporary files.
/// 
/// ## Parameters
/// 
/// * `dir` - Directory path to scan
/// 
/// ## Returns
/// 
/// * `Ok(Vec<PathBuf>)` - Sorted list of XML file paths
/// * `Err(std::io::Error)` - Directory reading failed
fn discover_xml_files(dir: &PathBuf) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut xml_files = Vec::new();
    
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && is_valid_xml_file(&path) {
            xml_files.push(path);
        }
    }
    
    // Sort alphabetically for deterministic processing order
    xml_files.sort();
    Ok(xml_files)
}

/// Check if a file is a valid XML configuration file
/// 
/// This function applies filtering rules to determine if a file should be
/// processed as an XML configuration file.
/// 
/// ## Filtering Rules
/// 
/// * Must end with .xml (case insensitive)
/// * Skip hidden files (starting with '.')
/// * Skip backup files (ending with '~', '.bak', '.orig')
/// * Skip temporary files (containing '.tmp')
/// 
/// ## Parameters
/// 
/// * `path` - File path to check
/// 
/// ## Returns
/// 
/// * `true` if the file should be processed
/// * `false` if the file should be skipped
fn is_valid_xml_file(path: &PathBuf) -> bool {
    if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
        // Skip hidden files and backup files
        if filename.starts_with('.') || 
           filename.ends_with('~') || 
           filename.ends_with(".bak") || 
           filename.ends_with(".orig") ||
           filename.contains(".tmp") {
            return false;
        }
        
        // Must have .xml extension (case insensitive)
        filename.to_lowercase().ends_with(".xml")
    } else {
        false
    }
}

/// Create a default configuration when no config files are found
/// 
/// This provides safe defaults when a directory is empty or no valid
/// configuration files can be loaded.
/// 
/// ## Returns
/// 
/// * `NacmConfig` with safe defaults (NACM disabled, deny-by-default)
fn create_default_config() -> NacmConfig {
    use std::collections::HashMap;
    
    NacmConfig {
        enable_nacm: false,  // Safe default when no configs found
        read_default: RuleEffect::Deny,
        write_default: RuleEffect::Deny,
        exec_default: RuleEffect::Deny,
        cmd_read_default: RuleEffect::Permit,
        cmd_exec_default: RuleEffect::Deny,
        log_if_default_permit: false,
        log_if_default_deny: false,
        groups: HashMap::new(),
        rule_lists: Vec::new(),
    }
}

/// Load and parse NACM configuration from single file
/// 
/// This helper function encapsulates the file loading and XML parsing logic
/// for a single configuration file.
/// 
/// ## Parameters
/// 
/// * `config_path` - Path to the NACM XML configuration file
/// 
/// ## Returns
/// 
/// * `Ok(NacmConfig)` - Successfully loaded and parsed configuration
/// * `Err(Box<dyn Error>)` - File not found, permission denied, invalid XML, etc.
/// 
/// ## Error Types
/// 
/// This function can return various error types:
/// - I/O errors (file not found, permission denied)
/// - XML parsing errors (malformed XML, unknown elements)
/// - NACM validation errors (invalid rule effects, unknown operations)
fn load_single_config(config_path: &PathBuf) -> Result<NacmConfig, Box<dyn std::error::Error>> {
    // Read the entire file into memory as a UTF-8 string
    // This will fail if the file doesn't exist or isn't readable
    let xml_content = std::fs::read_to_string(config_path)?;
    
    // Parse the XML content using our library's parsing function
    // This can fail for malformed XML or invalid NACM content
    NacmConfig::from_xml(&xml_content)
}

/// Handle single access request validation
/// 
/// This function processes a single access request using command-line arguments
/// and outputs the result according to the specified format. After displaying
/// results, it exits with an appropriate code for shell script integration.
/// 
/// ## Parameters
/// 
/// * `config` - Loaded NACM configuration
/// * `cli` - Parsed command-line arguments
/// * `user` - Username making the request (validated to be present)
/// * `operation` - Operation type (validated to be present)
/// 
/// ## Exit Codes
/// 
/// This function always calls `process::exit()`:
/// - Code 0: Access permitted
/// - Code 1: Access denied
fn handle_single_request(config: &NacmConfig, cli: &Cli, user: &str, operation: &OperationArg) {
    // Convert CLI operation argument to library operation type
    // This conversion is infallible (never panics) due to the From impl
    let operation = operation.clone().into();
    
    // Convert CLI context argument to library context type (if provided)
    let context = cli.context.as_ref().map(|ctx| ctx.clone().into());
    
    // Build the access request from command-line arguments
    // Uses borrowed string slices for efficiency (no copying)
    let request = AccessRequest {
        user,
        module_name: cli.module.as_deref(),    // Convert Option<String> to Option<&str>
        rpc_name: cli.rpc.as_deref(),
        operation,
        path: cli.path.as_deref(),
        context: context.as_ref(), // Convert Option<RequestContext> to Option<&RequestContext>
        command: cli.command.as_deref(), // Convert Option<String> to Option<&str>
    };

    // Perform the actual NACM validation using our library
    let result = config.validate(&request);
    
    // Output results in the requested format
    output_result(&result, &request, config, &cli.format, cli.verbose);
    
    // Set exit code based on access decision
    // This is crucial for shell script integration
    match result.effect {
        RuleEffect::Permit => process::exit(0),  // Success: access granted
        RuleEffect::Deny => process::exit(1),    // Failure: access denied
    }
}

/// Handle JSON input from stdin (streaming mode)
/// 
/// This function processes JSON requests line-by-line from standard input,
/// making it suitable for shell pipelines and streaming use cases. Each
/// line should contain a single JSON request object.
/// 
/// ## Input Format
/// 
/// Each line of stdin should be a complete JSON object:
/// ```json
/// {"user": "admin", "operation": "read", "module": "example"}
/// {"user": "operator", "operation": "execute", "rpc": "restart"}
/// ```
/// 
/// ## Output Format
/// 
/// For each valid input line, outputs a JSON result:
/// ```json
/// {"decision": "permit", "user": "admin", "operation": "read", ...}
/// {"decision": "deny", "user": "operator", "operation": "execute", ...}
/// ```
/// 
/// ## Error Handling
/// 
/// - Invalid JSON lines are logged to stderr but don't stop processing
/// - Invalid operations are logged and skipped
/// - I/O errors terminate the processing loop
/// 
/// ## Parameters
/// 
/// * `config` - Loaded NACM configuration for validation
/// * `cli` - Command-line arguments (mainly for format settings)
fn handle_json_input(config: &NacmConfig, _cli: &Cli) {
    use std::io::{self, BufRead};
    
    // Create a buffered reader from stdin for line-by-line processing
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        match line {
            Ok(json_str) => {
                // Try to parse each line as a JSON request
                match serde_json::from_str::<JsonRequest>(&json_str) {
                    Ok(json_req) => {
                        // Parse the operation string into our Operation enum
                        let operation = match json_req.operation.parse::<Operation>() {
                            Ok(op) => op,
                            Err(e) => {
                                eprintln!("Invalid operation '{}': {}", json_req.operation, e);
                                continue; // Skip this request and continue with next
                            }
                        };
                        
                        // Parse the context string into our RequestContext enum (if provided)
                        let context = match &json_req.context {
                            Some(ctx_str) => {
                                match ctx_str.to_lowercase().as_str() {
                                    "netconf" => Some(RequestContext::NETCONF),
                                    "cli" => Some(RequestContext::CLI),
                                    "webui" => Some(RequestContext::WebUI),
                                    _ => {
                                        eprintln!("Invalid context '{}': must be 'netconf', 'cli', or 'webui'", ctx_str);
                                        continue; // Skip this request and continue with next
                                    }
                                }
                            }
                            None => None,
                        };
                        
                        // Build the access request from JSON data
                        let request = AccessRequest {
                            user: &json_req.user,
                            module_name: json_req.module.as_deref(),
                            rpc_name: json_req.rpc.as_deref(),
                            operation,
                            path: json_req.path.as_deref(),
                            context: context.as_ref(), // Convert Option<RequestContext> to Option<&RequestContext>
                            command: json_req.command.as_deref(), // Convert Option<String> to Option<&str>
                        };

                        // Validate the request using NACM
                        let result = config.validate(&request);
                        
                        // Build JSON response with complete traceability
                        let json_result = JsonResult {
                            decision: match result.effect {
                                RuleEffect::Permit => "permit".to_string(),
                                RuleEffect::Deny => "deny".to_string(),
                            },
                            user: json_req.user,
                            module: json_req.module,
                            rpc: json_req.rpc,
                            operation: json_req.operation,
                            path: json_req.path,
                            context: json_req.context,
                            command: json_req.command,
                            config_loaded: true,
                            should_log: result.should_log,
                        };
                        
                        // Output result as compact JSON (one per line)
                        println!("{}", serde_json::to_string(&json_result).unwrap());
                    }
                    Err(e) => {
                        // Log JSON parsing errors but continue processing
                        eprintln!("Invalid JSON: {}", e);
                    }
                }
            }
            Err(e) => {
                // I/O errors are more serious - terminate processing
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }
}

/// Output validation results in the requested format
/// 
/// This function handles the formatting and display of NACM validation results.
/// It supports multiple output formats for different use cases: human-readable
/// text for interactive use and JSON for programmatic consumption.
/// 
/// ## Output Formats
/// 
/// **Text Format** (default):
/// ```
/// Decision: PERMIT [LOGGED]
/// User: admin
/// Operation: read
/// Module: example-module
/// Context: cli
/// Command: show status
/// ```
/// 
/// **JSON Format**:
/// ```json
/// {
///   "decision": "permit", 
///   "user": "admin",
///   "operation": "read",
///   "module": "example-module",
///   "context": "cli",
///   "command": "show status",
///   "should_log": true
/// }
/// ```
/// 
/// ## Verbosity Levels
/// 
/// In verbose mode, additional information is displayed:
/// - Configuration statistics (groups, rules)
/// - Rule matching details
/// - NACM enforcement status
/// 
/// ## Parameters
/// 
/// * `result` - The validation result with access decision and logging flag
/// * `request` - Original access request details
/// * `config` - NACM configuration (for verbose output)
/// * `format` - Output format selection
/// * `verbose` - Whether to include additional details
fn output_result(
    result: &nacm_validator::ValidationResult,
    request: &AccessRequest,
    _config: &NacmConfig,
    format: &OutputFormat,
    verbose: bool,
) {
    match format {
        OutputFormat::Text => {
            // Human-readable text output
            let decision = match result.effect {
                RuleEffect::Permit => "PERMIT",
                RuleEffect::Deny => "DENY",
            };
            
            let log_indicator = if result.should_log { " [LOGGED]" } else { "" };
            
            // In verbose mode, show detailed request information
            if verbose {
                println!("User: {}", request.user);
                if let Some(module) = request.module_name {
                    println!("Module: {}", module);
                }
                if let Some(rpc) = request.rpc_name {
                    println!("RPC: {}", rpc);
                }
                println!("Operation: {:?}", request.operation);
                if let Some(path) = request.path {
                    println!("Path: {}", path);
                }
                if let Some(context) = request.context {
                    println!("Context: {:?}", context);
                }
                if let Some(command) = request.command {
                    println!("Command: {}", command);
                }
                println!("Decision: {}{}", decision, log_indicator);
            } else {
                // Simple mode: show decision with log indicator
                println!("{}{}", decision, log_indicator);
            }
        }
        OutputFormat::Json => {
            // Structured JSON output for programmatic consumption
            let json_result = JsonResult {
                decision: match result.effect {
                    RuleEffect::Permit => "permit".to_string(),
                    RuleEffect::Deny => "deny".to_string(),
                },
                user: request.user.to_string(),
                module: request.module_name.map(|s| s.to_string()),
                rpc: request.rpc_name.map(|s| s.to_string()),
                operation: format!("{:?}", request.operation).to_lowercase(),
                path: request.path.map(|s| s.to_string()),
                context: request.context.map(|ctx| format!("{:?}", ctx).to_lowercase()),
                command: request.command.map(|s| s.to_string()),
                config_loaded: true,
                should_log: result.should_log,
            };
            
            // Pretty-print JSON for readability
            println!("{}", serde_json::to_string_pretty(&json_result).unwrap());
        }
        OutputFormat::ExitCode => {
            // Silent mode: only use exit codes, no text output
            // This is useful for shell scripts that only care about success/failure
        }
    }
}
