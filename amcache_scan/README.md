# Amcache_Scan

How to use Amcache_Scan Autopsy Plugin:

1. Place files in %AppData%\Roaming\Autopsy\Python_modules
2. In Configure Ingest Modules, select Amcache Scan.
3. Enter your VirusTotal API Key. Select the 'Private API Key?' Checkbox if you have private VirusTotal API Key.

The module will parse the following keys:<br />
- Amcache.hve\\Root\\File
- Amcache.hve\\Root\\Programs
- Amcache.hve\\Root\\InventoryApplicationFile
- Amcache.hve\\Root\\InventoryDeviceContainer
- Amcache.hve\\Root\\InventoryDevicePnp
- Amcache.hve\\Root\\InventoryDriverBinary
- Amcache.hve\\Root\\InventoryDriverPackage
- Amcache.hve\\Root\\InventoryApplicationShortcut

After the keys are parsed, the results are added to Autopsy, then the SHA1 hashes from Amcache.hve\\Root\\File\\ and Amcache.hve\\Root\\InventoryApplicationFile Registry keys and searched for in VirusTotal.
