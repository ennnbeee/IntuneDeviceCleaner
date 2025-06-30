# ♻ IntuneDeviceCleaner

IntuneDeviceCleaner is a PowerShell based utility that allows for granular filtering of stale devices, allowing you to only retire specific devices to keep Intune clean and tidy.

It currently supports the following filtering options:

- Operating System
- Device Ownership
- Entra join type
- MDM type

Additional filters will become available with new releases.

## ⚠ Public Preview Notice

IntuneDeviceCleaner is currently in Public Preview, meaning that although the it is functional, you may encounter issues or bugs with the script.

> [!TIP]
> If you do encounter bugs, want to contribute, submit feedback or suggestions, please create an issue.

## 🗒 Prerequisites

> [!IMPORTANT]
>
> - Supports PowerShell 7 on Windows
> - `Microsoft.Graph.Authentication` module should be installed, the script will detect and install if required.
> - Entra ID App Registration with appropriate Graph Scopes or using Interactive Sign-In with a privileged account.

## 🔄 Updates

- **v0.1**
  - Initial release

## 🔑 Permissions

The PowerShell script requires the below Graph API permissions, you can create an Entra ID App Registration with the following Graph API Application permissions:

- `DeviceManagementManagedDevices.ReadWrite.All`
- `DeviceManagementManagedDevices.PrivilegedOperations.All`

## ⏯ Usage

Download the `IntuneDeviceCleaner.ps1` script, and from the saved location in a standard or elevated PowerShell prompt run one of the following:

### 🧪 Testing

Run the script to retire all Intune devices that have not checked in within **60** days in **whatIf** mode where no devices are retired:

```powershell
.\IntuneDeviceCleaner.ps1 -deviceCheckInDays 60 -whatIf $true
```

### 📱 Android Devices

Run the script to retire all **Android** Intune devices that have not checked in within **60** days:

```powershell
.\IntuneDeviceCleaner.ps1 -deviceCheckInDays 60 -operatingSystem android
```

### ☁🖥 Entra Joined Windows Devices

Run the script to retire all **Entra Joined** **Windows** Intune devices that have not checked in within **30** days:

```powershell
.\IntuneDeviceCleaner.ps1 -deviceCheckInDays 30 -operatingSystem windows -joinType azureADJoined
```

### ☁🗒🏢 Entra Registered Corporate Devices

Run the script to retire all **Entra Registered** **Corporate owned** Intune devices that have not checked in within **100** days:

```powershell
.\IntuneDeviceCleaner.ps1 -deviceCheckInDays 100 -ownershipType company -joinType azureADRegistered
```

## 🎬 Demos

Coming soon

## 🚑 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/ennnbeee/IntuneDeviceCleaner/issues) page
2. Open a new issue if needed

Thank you for your support.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Created by [Nick Benton](https://github.com/ennnbeee) of [odds+endpoints](https://www.oddsandendpoints.co.uk/)
