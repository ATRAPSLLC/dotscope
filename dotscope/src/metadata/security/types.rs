//! Declarative security: the action a `DeclSecurity` row takes, the formats its permission set
//! blob comes in, the well-known permission classes and `SecurityPermissionFlag`.
//!
//! A `DeclSecurity` row (ECMA-335 II.22.11) attaches a permission set to an assembly, type or
//! method, with an action that says what the runtime does with it: demand it of callers, assert
//! it, request it for the assembly, and so on.
//!
//! # Examples
//!
//! ```rust
//! use dotscope::metadata::security::SecurityAction;
//!
//! // The Action column of an assembly-level request for the minimum permissions it needs
//! assert_eq!(SecurityAction::from(8), SecurityAction::RequestMinimum);
//! assert_eq!(u16::from(SecurityAction::LinkDemand), 6);
//! assert_eq!(SecurityAction::RequestMinimum.to_string(), "reqmin");
//! ```

use std::{
    fmt::{self, Display},
    sync::Arc,
};

use crate::metadata::security::PermissionSet;

/// A declarative security entry: the action and the permission set it applies to.
pub struct Security {
    /// What the runtime does with the permission set
    pub action: SecurityAction,

    /// The permissions the declaration names
    pub permission_set: Arc<PermissionSet>,
}

/// The `Action` column of a `DeclSecurity` row: `System.Security.Permissions.SecurityAction`,
/// whose values the runtime's `CorDeclSecurity` names.
///
/// [`Display`] gives the ILAsm keyword (ECMA-335 II.20), and for a value the runtime does
/// not define the bare number, which ILAsm also accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityAction {
    /// `request` (1): the permissions the code requests.
    Request,
    /// `demand` (2): every caller on the stack must hold the permissions.
    Demand,
    /// `assert` (3): callers need not hold the permissions this code holds.
    Assert,
    /// `deny` (4): access through the permissions is refused to the code this calls.
    Deny,
    /// `permitonly` (5): only these permissions are available to the code this calls.
    PermitOnly,
    /// `linkcheck` (6): the immediate caller must hold the permissions, checked at JIT time.
    LinkDemand,
    /// `inheritcheck` (7): a derived type or overriding method must hold the permissions.
    InheritanceDemand,
    /// `reqmin` (8): the assembly needs the permissions to run.
    RequestMinimum,
    /// `reqopt` (9): the assembly can use the permissions but runs without them.
    RequestOptional,
    /// `reqrefuse` (10): the assembly must not be granted the permissions.
    RequestRefuse,
    /// `prejitgrant` (11): the permissions granted when the code was precompiled.
    PrejitGrant,
    /// `prejitdeny` (12): the permissions denied when the code was precompiled.
    PrejitDeny,
    /// `noncasdemand` (13): a demand for permissions that are not code access permissions.
    NonCasDemand,
    /// `noncaslinkdemand` (14): a link demand for non-code-access permissions.
    NonCasLinkDemand,
    /// `noncasinheritance` (15): an inheritance demand for non-code-access permissions.
    NonCasInheritance,
    /// A value the runtime does not define
    Unknown(u16),
}

impl Display for SecurityAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityAction::Request => write!(f, "request"),
            SecurityAction::Demand => write!(f, "demand"),
            SecurityAction::Assert => write!(f, "assert"),
            SecurityAction::Deny => write!(f, "deny"),
            SecurityAction::PermitOnly => write!(f, "permitonly"),
            SecurityAction::LinkDemand => write!(f, "linkcheck"),
            SecurityAction::InheritanceDemand => write!(f, "inheritcheck"),
            SecurityAction::RequestMinimum => write!(f, "reqmin"),
            SecurityAction::RequestOptional => write!(f, "reqopt"),
            SecurityAction::RequestRefuse => write!(f, "reqrefuse"),
            SecurityAction::PrejitGrant => write!(f, "prejitgrant"),
            SecurityAction::PrejitDeny => write!(f, "prejitdeny"),
            SecurityAction::NonCasDemand => write!(f, "noncasdemand"),
            SecurityAction::NonCasLinkDemand => write!(f, "noncaslinkdemand"),
            SecurityAction::NonCasInheritance => write!(f, "noncasinheritance"),
            SecurityAction::Unknown(v) => write!(f, "{v}"),
        }
    }
}

impl From<SecurityAction> for u16 {
    fn from(action: SecurityAction) -> Self {
        match action {
            SecurityAction::Request => 1,
            SecurityAction::Demand => 2,
            SecurityAction::Assert => 3,
            SecurityAction::Deny => 4,
            SecurityAction::PermitOnly => 5,
            SecurityAction::LinkDemand => 6,
            SecurityAction::InheritanceDemand => 7,
            SecurityAction::RequestMinimum => 8,
            SecurityAction::RequestOptional => 9,
            SecurityAction::RequestRefuse => 10,
            SecurityAction::PrejitGrant => 11,
            SecurityAction::PrejitDeny => 12,
            SecurityAction::NonCasDemand => 13,
            SecurityAction::NonCasLinkDemand => 14,
            SecurityAction::NonCasInheritance => 15,
            SecurityAction::Unknown(value) => value,
        }
    }
}

impl From<u16> for SecurityAction {
    fn from(value: u16) -> Self {
        match value {
            1 => SecurityAction::Request,
            2 => SecurityAction::Demand,
            3 => SecurityAction::Assert,
            4 => SecurityAction::Deny,
            5 => SecurityAction::PermitOnly,
            6 => SecurityAction::LinkDemand,
            7 => SecurityAction::InheritanceDemand,
            8 => SecurityAction::RequestMinimum,
            9 => SecurityAction::RequestOptional,
            10 => SecurityAction::RequestRefuse,
            11 => SecurityAction::PrejitGrant,
            12 => SecurityAction::PrejitDeny,
            13 => SecurityAction::NonCasDemand,
            14 => SecurityAction::NonCasLinkDemand,
            15 => SecurityAction::NonCasInheritance,
            _ => SecurityAction::Unknown(value),
        }
    }
}

/// The full names of the .NET Framework's permission classes.
///
/// An XML permission set names a permission by its class; a binary one (what compilers emit)
/// by the permission attribute's class, this name with `Attribute` after it, and both
/// qualify the name with its assembly. [`crate::metadata::security::Permission::is_class`]
/// matches either.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::security::security_classes;
///
/// fn is_network_permission(type_name: &str) -> bool {
///     matches!(
///         type_name,
///         security_classes::DNS_PERMISSION
///             | security_classes::SOCKET_PERMISSION
///             | security_classes::WEB_PERMISSION
///     )
/// }
///
/// assert!(is_network_permission("System.Net.WebPermission"));
/// ```
pub mod security_classes {
    /// `FileIOPermission`: read, write, append and path discovery access to files and
    /// directories (`Read`, `Write`, `Append`, `PathDiscovery`, `Unrestricted`).
    pub const FILE_IO_PERMISSION: &str = "System.Security.Permissions.FileIOPermission";

    /// `SecurityPermission`: the operations [`super::SecurityPermissionFlags`] names
    /// (`Flags`, one boolean property per flag, `Unrestricted`).
    pub const SECURITY_PERMISSION: &str = "System.Security.Permissions.SecurityPermission";

    /// `RegistryPermission`: access to registry keys (`Read`, `Write`, `Create`, `Unrestricted`).
    pub const REGISTRY_PERMISSION: &str = "System.Security.Permissions.RegistryPermission";

    /// `EnvironmentPermission`: access to environment variables (`Read`, `Write`,
    /// `Unrestricted`).
    pub const ENVIRONMENT_PERMISSION: &str = "System.Security.Permissions.EnvironmentPermission";

    /// `ReflectionPermission`: reflection over non-public members and emitting code (`Flags`,
    /// `MemberAccess`, `ReflectionEmit`, `Unrestricted`).
    pub const REFLECTION_PERMISSION: &str = "System.Security.Permissions.ReflectionPermission";

    /// `UIPermission`: windows and the clipboard (`Window`, `Clipboard`, `Unrestricted`).
    pub const UI_PERMISSION: &str = "System.Security.Permissions.UIPermission";

    /// `PrincipalPermission`: the identity and role of the current principal (`Name`, `Role`,
    /// `Authenticated`).
    pub const PRINCIPAL_PERMISSION: &str = "System.Security.Permissions.PrincipalPermission";

    /// `DnsPermission`: resolving host names (`Unrestricted`).
    pub const DNS_PERMISSION: &str = "System.Net.DnsPermission";

    /// `SocketPermission`: connecting and accepting sockets (`Access`, `Host`, `Port`,
    /// `Transport`, `Unrestricted`).
    pub const SOCKET_PERMISSION: &str = "System.Net.SocketPermission";

    /// `WebPermission`: HTTP access to URIs (`Connect`, `Accept`, `ConnectPattern`,
    /// `AcceptPattern`, `Unrestricted`).
    pub const WEB_PERMISSION: &str = "System.Net.WebPermission";

    /// `IsolatedStorageFilePermission`: isolated storage (`UsageAllowed`, `UserQuota`,
    /// `Unrestricted`).
    pub const STORAGE_PERMISSION: &str =
        "System.Security.Permissions.IsolatedStorageFilePermission";

    /// `KeyContainerPermission`: cryptographic key containers (`Flags`, `KeyContainerName`,
    /// `Unrestricted`).
    pub const KEY_CONTAINER_PERMISSION: &str = "System.Security.Permissions.KeyContainerPermission";

    /// `StorePermission`: X.509 certificate stores (`Flags`, `Unrestricted`).
    pub const STORE_PERMISSION: &str = "System.Security.Permissions.StorePermission";

    /// `EventLogPermission`: event logs (`MachineName`, `PermissionAccess`, `Unrestricted`).
    pub const EVENT_LOG_PERMISSION: &str = "System.Diagnostics.EventLogPermission";

    /// `PerformanceCounterPermission`: performance counters (`CategoryName`, `MachineName`,
    /// `PermissionAccess`, `Unrestricted`).
    pub const PERF_COUNTER_PERMISSION: &str = "System.Diagnostics.PerformanceCounterPermission";

    /// `PermissionSet`: the root element of an XML permission set, unrestricted when its
    /// `Unrestricted` attribute is `true`.
    pub const PERMISSION_SET: &str = "System.Security.PermissionSet";

    /// `PermissionSetAttribute`: a whole permission set in a binary one, unrestricted when its
    /// `Unrestricted` property is `true`.
    pub const PERMISSION_SET_ATTRIBUTE: &str = "System.Security.Permissions.PermissionSetAttribute";
}

/// The format of a permission set blob, which its first byte tells.
///
/// The runtime reads a blob that starts with `.` as the binary format, and any other as XML
/// in UTF-16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionSetFormat {
    /// XML text, `<PermissionSet>` with an `<IPermission>` element per permission, written
    /// by .NET Framework 1.x compilers.
    Xml,

    /// The binary format compilers write since .NET Framework 2.0 (ECMA-335 II.22.11): `.`, a
    /// compressed count, and per permission its attribute class's assembly-qualified name and
    /// its properties as custom attribute named arguments.
    Binary,

    /// Data in neither format.
    Unknown,
}

metadata_flags! {
    /// `System.Security.Permissions.SecurityPermissionFlag`: the operations a
    /// `SecurityPermission` grants. The enum is an `int` in the framework, and its values are
    /// written as one.
    pub struct SecurityPermissionFlags(i32);
}

impl SecurityPermissionFlags {
    /// `Assertion`: assert that the code's callers hold permissions they may not.
    pub const SECURITY_FLAG_ASSERTION: Self = Self(0x0000_0001);
    /// `UnmanagedCode`: call unmanaged code.
    pub const SECURITY_FLAG_UNMANAGED_CODE: Self = Self(0x0000_0002);
    /// `SkipVerification`: run code that is not verified.
    pub const SECURITY_FLAG_SKIP_VERIFICATION: Self = Self(0x0000_0004);
    /// `Execution`: run at all.
    pub const SECURITY_FLAG_EXECUTION: Self = Self(0x0000_0008);
    /// `ControlThread`: manipulate threads.
    pub const SECURITY_FLAG_CONTROL_THREAD: Self = Self(0x0000_0010);
    /// `ControlEvidence`: provide evidence and alter it.
    pub const SECURITY_FLAG_CONTROL_EVIDENCE: Self = Self(0x0000_0020);
    /// `ControlPolicy`: view and modify security policy.
    pub const SECURITY_FLAG_CONTROL_POLICY: Self = Self(0x0000_0040);
    /// `SerializationFormatter`: use a serialization formatter.
    pub const SECURITY_FLAG_SERIALIZATION_FORMATTER: Self = Self(0x0000_0080);
    /// `ControlDomainPolicy`: set an application domain's policy.
    pub const SECURITY_FLAG_CONTROL_DOMAIN_POLICY: Self = Self(0x0000_0100);
    /// `ControlPrincipal`: manipulate the principal object.
    pub const SECURITY_FLAG_CONTROL_PRINCIPAL: Self = Self(0x0000_0200);
    /// `ControlAppDomain`: create and manipulate application domains.
    pub const SECURITY_FLAG_CONTROL_APPDOMAIN: Self = Self(0x0000_0400);
    /// `RemotingConfiguration`: configure remoting types and channels.
    pub const SECURITY_FLAG_REMOTING_CONFIGURATION: Self = Self(0x0000_0800);
    /// `Infrastructure`: plug into the runtime's infrastructure.
    pub const SECURITY_FLAG_INFRASTRUCTURE: Self = Self(0x0000_1000);
    /// `BindingRedirects`: redirect assembly binding in the configuration file.
    pub const SECURITY_FLAG_BINDING_REDIRECTS: Self = Self(0x0000_2000);

    /// `AllFlags`: every flag.
    pub const ALL: Self = Self(0x0000_3FFF);

    /// The flag names `SecurityPermissionFlag` defines, as its `ToString` writes them.
    const NAMES: [(&'static str, Self); 16] = [
        ("NoFlags", Self::ZERO),
        ("Assertion", Self::SECURITY_FLAG_ASSERTION),
        ("UnmanagedCode", Self::SECURITY_FLAG_UNMANAGED_CODE),
        ("SkipVerification", Self::SECURITY_FLAG_SKIP_VERIFICATION),
        ("Execution", Self::SECURITY_FLAG_EXECUTION),
        ("ControlThread", Self::SECURITY_FLAG_CONTROL_THREAD),
        ("ControlEvidence", Self::SECURITY_FLAG_CONTROL_EVIDENCE),
        ("ControlPolicy", Self::SECURITY_FLAG_CONTROL_POLICY),
        (
            "SerializationFormatter",
            Self::SECURITY_FLAG_SERIALIZATION_FORMATTER,
        ),
        (
            "ControlDomainPolicy",
            Self::SECURITY_FLAG_CONTROL_DOMAIN_POLICY,
        ),
        ("ControlPrincipal", Self::SECURITY_FLAG_CONTROL_PRINCIPAL),
        ("ControlAppDomain", Self::SECURITY_FLAG_CONTROL_APPDOMAIN),
        (
            "RemotingConfiguration",
            Self::SECURITY_FLAG_REMOTING_CONFIGURATION,
        ),
        ("Infrastructure", Self::SECURITY_FLAG_INFRASTRUCTURE),
        ("BindingRedirects", Self::SECURITY_FLAG_BINDING_REDIRECTS),
        ("AllFlags", Self::ALL),
    ];

    /// Returns `true` if every flag is set.
    #[must_use]
    pub const fn is_all(self) -> bool {
        (self.0 & Self::ALL.0) == Self::ALL.0
    }

    /// The flags `text` names as an XML permission set writes them: flag names or integers,
    /// separated by commas (`"UnmanagedCode, SkipVerification"`).
    ///
    /// Returns `None` when a part is neither a name the enum defines nor an integer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::security::SecurityPermissionFlags;
    ///
    /// let flags = SecurityPermissionFlags::parse("UnmanagedCode, Execution").unwrap();
    /// assert_eq!(flags.bits(), 0x0A);
    /// assert!(SecurityPermissionFlags::parse("AllFlags").unwrap().is_all());
    /// assert!(SecurityPermissionFlags::parse("Unknown").is_none());
    /// ```
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        text.split(',')
            .map(str::trim)
            .try_fold(Self::ZERO, |flags, part| {
                let flag = Self::NAMES
                    .iter()
                    .find(|(name, _)| *name == part)
                    .map(|(_, flag)| *flag)
                    .or_else(|| part.parse::<i32>().ok().map(Self))?;
                Some(Self(flags.0 | flag.0))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_have_the_runtimes_values() {
        let actions = [
            (1, SecurityAction::Request),
            (2, SecurityAction::Demand),
            (3, SecurityAction::Assert),
            (4, SecurityAction::Deny),
            (5, SecurityAction::PermitOnly),
            (6, SecurityAction::LinkDemand),
            (7, SecurityAction::InheritanceDemand),
            (8, SecurityAction::RequestMinimum),
            (9, SecurityAction::RequestOptional),
            (10, SecurityAction::RequestRefuse),
            (11, SecurityAction::PrejitGrant),
            (12, SecurityAction::PrejitDeny),
            (13, SecurityAction::NonCasDemand),
            (14, SecurityAction::NonCasLinkDemand),
            (15, SecurityAction::NonCasInheritance),
        ];
        for (value, action) in actions {
            assert_eq!(SecurityAction::from(value), action);
            assert_eq!(u16::from(action), value);
        }
        assert_eq!(SecurityAction::from(0), SecurityAction::Unknown(0));
        assert_eq!(SecurityAction::from(16), SecurityAction::Unknown(16));
        assert_eq!(u16::from(SecurityAction::Unknown(0x9999)), 0x9999);
        assert_eq!(
            SecurityAction::NonCasInheritance.to_string(),
            "noncasinheritance"
        );
        assert_eq!(SecurityAction::Unknown(99).to_string(), "99");
    }

    #[test]
    fn flags_have_the_frameworks_values() {
        assert_eq!(
            SecurityPermissionFlags::SECURITY_FLAG_UNMANAGED_CODE.bits(),
            2
        );
        assert_eq!(
            SecurityPermissionFlags::SECURITY_FLAG_BINDING_REDIRECTS.bits(),
            0x2000
        );
        let every = SecurityPermissionFlags::NAMES
            .iter()
            .filter(|(name, _)| *name != "AllFlags")
            .fold(0, |bits, (_, flag)| bits | flag.bits());
        assert_eq!(every, SecurityPermissionFlags::ALL.bits());
    }

    #[test]
    fn flags_parse_from_names_and_integers() {
        let parse = |text| SecurityPermissionFlags::parse(text).map(SecurityPermissionFlags::bits);
        assert_eq!(parse("SkipVerification"), Some(4));
        assert_eq!(parse("Assertion,  ControlThread"), Some(0x11));
        assert_eq!(parse("NoFlags"), Some(0));
        assert_eq!(parse("8"), Some(8));
        assert_eq!(parse("AllFlags"), Some(0x3FFF));
        assert_eq!(parse("Execution, Bogus"), None);
        assert_eq!(parse(""), None);
    }
}
