# This python autopsy module will export the Amcache Registry Hive, parse
# eight keys and write the results to sqlite database. The eight Registry keys
# are as follows: 
#    - Amcache.hve\Root\File\*?\*?
#    - Amcache.hve\Root\Programs\*? 
#    - Amcache.hve\Root\InventoryApplicationFile\*?
#    - Amcache.hve\Root\InventoryDeviceContainer\*?
#    - Amcache.hve\Root\InventoryDevicePnp\*?
#    - Amcache.hve\Root\InventoryDriverBinary\*?
#    - Amcache.hve\Root\InventoryDriverPackage\*?
#    - Amcache.hve\Root\InventoryApplicationShortcut\*?
# After the keys are parsed, the SHA1 hashes in the Amcache.hve\Root\File\*?\?
# and Amcache.hve\Inventory\ApplicationFile\*? keys are compared against
# VirusTotal.
#
# Contact: Rebecca Anderson rander16 <at> GMU [dot] EDU
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# Comments 
#   Version 1.0 - Initial version - September 2018
# 

import jarray
import inspect
import os
import subprocess
import time

from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import ButtonGroup
from javax.swing import JTextField
from javax.swing import JLabel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JScrollPane
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter

from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class AmcacheScanIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Amcache Scan"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Send Amcache SHA1 hashes to VirusTotal"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return AmcacheScanWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, AmcacheScanWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return AmcacheScanWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return AmcacheScanIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class AmcacheScanIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(AmcacheScanIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_tables = []
        self.List_Of_AmcacheScan = []

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context
        self.API_Key = self.local_settings.getAPI_Key()
        self.Private = self.local_settings.getPrivate()
        self.root_file_exists = 0
        self.root_file_count = 0
        self.inventory_application_file_exists = 0
        self.inventory_application_file_count = 0
        self.count = 0
        self.sum = 0

        #Record Parameters
        self.log(Level.INFO, "API_Key: " + str(self.API_Key))
        self.log(Level.INFO, "Private: " + str(self.Private))

        self.my_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "amcache2sqlite.exe")
        if not os.path.exists(self.my_exe):
            raise IngestModuleException("EXE was not found in module folder")

       #create my tables
        self.List_Of_tables.append('root_file')
        self.List_Of_tables.append('root_programs')
        self.List_Of_tables.append('inventory_application_file')
        self.List_Of_tables.append('inventory_device_container')
        self.List_Of_tables.append('inventory_device_pnp')
        self.List_Of_tables.append('inventory_driver_binary')
        self.List_Of_tables.append('inventory_driver_package')
        self.List_Of_tables.append('inventory_application_shortcut')
        #self.List_Of_tables.append('inventory_application_framework')
        self.List_Of_tables.append('root_file_virustotal_scan')
        self.List_Of_tables.append('inventory_application_file_virustotal_scan')

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See:x http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):

        if len(self.List_Of_tables) < 1:
            message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, self.moduleName, " Can't find my tables " )
            IngestServices.getInstance().postMessage(message)
            return IngestModule.ProcessResult.ERROR

        # Check if this is Windows
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
            return IngestModule.ProcessResult.OK

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "Amcache.hve")
        numFiles = len(files)
        self.log(Level.INFO, "found " + str(numFiles) + " files")
        fileCount = 0;

        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "Found temporary directory: " + Temp_Dir)

        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Amcache Scan", " Parsing Amcache.Hve " ) 
        IngestServices.getInstance().postMessage(message) 
        # Dump Amcache.hve files in the temp directory
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Temp_Dir, str(file.getId()) + '-amcache.hve')
            ContentUtils.writeToFile(file, File(lclDbPath))
            mydb = Temp_Dir + "\\" + str(file.getId()) + "-myAmcache.db3"
            # Parse some keys
            self.log(Level.INFO, "[Executable #1] Parsing Amcache.Hve: \"" + self.my_exe + "\" -r " + lclDbPath + " -d " + mydb)
            subprocess.Popen([self.my_exe, '-r', lclDbPath, '-d', mydb]).communicate()[0] 

            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % mydb)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + mydb + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
             
            
            for am_table_name in self.List_Of_tables: 
                if am_table_name == 'root_file_virustotal_scan': # <-- because we haven't run the executable these tables yet
                    continue
                if am_table_name == 'inventory_application_file_virustotal_scan':
                    continue
                try:
                    stmt = dbConn.createStatement()
                    resultSet = stmt.executeQuery("Select tbl_name from SQLITE_MASTER where lower(tbl_name) in ('" + am_table_name + "'); ")
                    self.log(Level.INFO, "query SQLite Master table for " + am_table_name)
                except SQLException as e:
                    self.log(Level.INFO, "Error querying database for table " + am_table_name + " (" + e.getMessage() + ")")
                    return IngestModule.ProcessResult.OK

                # Cycle through each row and create artifacts
                while resultSet.next():
                    try: 
                        self.log(Level.INFO, "Result (" + resultSet.getString("tbl_name") + ")")
                        table_name = resultSet.getString("tbl_name")
                        SQL_String_1 = "Select * from " + table_name + ";"
                        SQL_String_2 = "PRAGMA table_info('" + table_name + "')"
                        artifact_name = "TSK_" + table_name.upper()
                        artifact_desc = "Amcache " + table_name.upper()

                        try:
                            self.log(Level.INFO, "Begin Create New Artifacts")
                            artID_amc = skCase.addArtifactType( artifact_name, artifact_desc)
                        except:        
                            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

                        artID_amc = skCase.getArtifactTypeID(artifact_name)
                        artID_amc_evt = skCase.getArtifactType(artifact_name)
                       
                        Column_Names = []
                        Column_Types = []
                        resultSet2  = stmt.executeQuery(SQL_String_2)
                        while resultSet2.next(): 
                            Column_Names.append(resultSet2.getString("name").upper())
                            Column_Types.append(resultSet2.getString("type").upper())
                            if resultSet2.getString("type").upper() == "TEXT":
                                try:
                                    attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                                except:
                                    self.log(Level.INFO, "Attributes Creation Error (string), " + resultSet2.getString("name") + " ==> ")
                            elif resultSet2.getString("type").upper() == "":
                                try:
                                    attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, resultSet2.getString("name"))
                                except:        
                                    self.log(Level.INFO, "Attributes Creation Error (string2), " + resultSet2.getString("name") + " ==> ")
                            else:
                                try:
                                    attID_ex1 = skCase.addArtifactAttributeType("TSK_" + resultSet2.getString("name").upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, resultSet2.getString("name"))
                                except:        
                                    self.log(Level.INFO, "Attributes Creation Error (long), " + resultSet2.getString("name") + " ==> ")

                                             
                        resultSet3 = stmt.executeQuery(SQL_String_1)
                        while resultSet3.next():
                            art = file.newArtifact(artID_amc)
                            Column_Number = 1
                            for col_name in Column_Names:
                                c_name = "TSK_" + col_name
                                attID_ex1 = skCase.getAttributeType(c_name)
                                if Column_Types[Column_Number - 1] == "TEXT":
                                    art.addAttribute(BlackboardAttribute(attID_ex1, AmcacheScanIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                                elif Column_Types[Column_Number - 1] == "":
                                    art.addAttribute(BlackboardAttribute(attID_ex1, AmcacheScanIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                                else:
                                    art.addAttribute(BlackboardAttribute(attID_ex1, AmcacheScanIngestModuleFactory.moduleName, long(resultSet3.getInt(Column_Number))))
                                Column_Number = Column_Number + 1
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(AmcacheScanIngestModuleFactory.moduleName, artID_amc_evt, None))
                            
                    except SQLException as e:
                        self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")


                stmt.close()
            dbConn.close()
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Amcache Scan", " Amcache Keys Have Been Parsed " ) 
        IngestServices.getInstance().postMessage(message)
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Amcache Scan", " Beginning VirusTotal Scan " ) 
        IngestServices.getInstance().postMessage(message)

        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            mydb = Temp_Dir + "\\" + str(file.getId()) + "-myAmcache.db3"

            try:
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % mydb)
            except SQLException as e:
                self.Error_Message.setText("Error Opening Settings")

            # First check that the 'root_file' table exists
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = 'SELECT COUNT(*) as count FROM sqlite_master WHERE type = "table" AND name = "root_file";'
                resultSet = stmt.executeQuery(SQL_Statement)
                self.root_file_exists = int(resultSet.getString("count"))
            except:
                self.log(Level.INFO, "LOOK HERE: it's not working.")

            # If it does, count the number of rows in the table
            if self.root_file_exists: 
                self.log(Level.INFO, "root_file table exists. Counting rows.")
                try:
                    stmt = dbConn.createStatement()
                    SQL_Statement = 'SELECT count(*) AS count FROM root_file;'
                    resultSet = stmt.executeQuery(SQL_Statement)
                    self.root_file_count = int(resultSet.getString("count"))
                except:
                    self.log(Level.INFO, "LOOK HERE: it's not working.")

            # Now check that the 'inventory_application_file' table exists
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = 'SELECT COUNT(*) as count FROM sqlite_master WHERE type = "table" AND name = "inventory_application_file";'
                resultSet = stmt.executeQuery(SQL_Statement)
                self.inventory_application_file_exists = int(resultSet.getString("count"))
            except:
                self.log(Level.INFO, "LOOK HERE: it's not working.")

            # If it does, count the number of rows in the table
            if self.inventory_application_file_exists:
                self.log(Level.INFO, "inventory_application_file table exists. Counting rows.")
                try:
                    stmt = dbConn.createStatement()
                    SQL_Statement = 'SELECT count(*) AS count FROM inventory_application_file;'
                    resultSet = stmt.executeQuery(SQL_Statement)
                    self.inventory_application_file_count = int(resultSet.getString("count"))
                except:
                    self.log(Level.INFO, "LOOK HERE: it's not working.")
            stmt.close()
            dbConn.close()

            # Now we know how many files we need to scan
            # Use the sum, to give the user a progress bar
            self.sum = self.root_file_count + self.inventory_application_file_count
            progressBar.switchToDeterminate(self.sum)

            artifact_name = "TSK_" + 'root_file_virustotal_scan'.upper()
            artifact_desc = "Amcache " + 'root_file_virustotal_scan'.upper()

            try:
                self.log(Level.INFO, "Begin creating root_file_virustotal_scan Artifacts")
                artID_amc = skCase.addArtifactType(artifact_name, artifact_desc)
            except:        
                self.log(Level.INFO, "ARTIFACTS CREATION ERROR: root_file_virustotal_scan")

            artID_typeID = skCase.getArtifactTypeID(artifact_name)
            artID_type = skCase.getArtifactType(artifact_name)

            Column_Names = ["p_key","file","sha1","vt_positives","vt_ratio","vt_report_link"]
            Column_Types = ["int","text","text","int","text","text"]

            # A public VirusTotal API key only allows for 4 requests a minute (1/15 seconds)
            # Use this to track how much time has passed
            current_time = time.time()

            # start scanning root_file SHA1 hashes
            for i in range(0, self.root_file_count):
                subprocess.Popen([self.my_exe,'-d', mydb, '-a', self.API_Key, '-t', 'root_file', '-k', str(i + 1)]).communicate()[0]
                try: 
                    Class.forName("org.sqlite.JDBC").newInstance()
                    dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % mydb)
                except SQLException as e:
                    self.log(Level.INFO, "Could not open database file (not SQLite) " + mydb + " (" + e.getMessage() + ")")
                    return IngestModule.ProcessResult.OK

                if i == 0:
                    try:
                        stmt = dbConn.createStatement()
                        resultSet = stmt.executeQuery('SELECT COUNT(*) as count FROM sqlite_master WHERE type = "table" AND name = "root_file_virustotal_scan";')
                        self.log(Level.INFO, "query SQLite Master table for root_file_virustotal_scan")
                    except SQLException as e:
                       self.log(Level.INFO, "Error querying database for table root_file_virustotal_scan (" + e.getMessage() + ")")
                    if int(resultSet.getString("count")):
                        self.log(Level.INFO, "root_file_virustotal_scan found")
                        for j in range(0,len(Column_Names)):
                            if Column_Types[j].upper() == "TEXT":
                                try:
                                    attID_ex1 = skCase.addArtifactAttributeType("TSK_" + Column_Names[j].upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, Column_Names[j])
                                except:        
                                    self.log(Level.INFO, "Attributes Creation Error, " + Column_Names[j] + " ==> ")
                            else:
                                try:
                                    attID_ex1 = skCase.addArtifactAttributeType("TSK_" + Column_Names[j].upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, Column_Names[j])
                                except:        
                                    self.log(Level.INFO, "Attributes Creation Error, " + Column_Names[j] + " ==> ")
                    stmt.close()

                SQL_String_1 = 'SELECT "p_key","file","sha1","vt_positives","vt_ratio","vt_report_link" from "root_file_virustotal_scan" WHERE p_key = ' + str(i + 1) + ';'
                stmt = dbConn.createStatement()
                resultSet3 = stmt.executeQuery(SQL_String_1)
                while resultSet3.next():
                    art = file.newArtifact(artID_typeID)
                    Column_Number = 1
                    for col_name in Column_Names:
                        c_name = "TSK_" + col_name.upper()
                        attID_ex1 = skCase.getAttributeType(c_name)
                        if Column_Types[Column_Number - 1].upper() == "TEXT":
		                    art.addAttribute(BlackboardAttribute(attID_ex1, AmcacheScanIngestModuleFactory.moduleName, resultSet3.getString(col_name)))
                        elif Column_Types[Column_Number - 1] == "":
                            art.addAttribute(BlackboardAttribute(attID_ex1, AmcacheScanIngestModuleFactory.moduleName, resultSet3.getString(col_name)))
                        else:
                            art.addAttribute(BlackboardAttribute(attID_ex1, AmcacheScanIngestModuleFactory.moduleName, long(resultSet3.getInt(col_name))))
                        Column_Number = Column_Number + 1
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(AmcacheScanIngestModuleFactory.moduleName, artID_type, None))
                stmt.close()
                dbConn.close()

                if not self.Private:
                    after_time = time.time()
                    diff = current_time - after_time
                    time.sleep(15 - diff)
                    current_time = time.time()
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK
                self.count += 1
                progressBar.progress(self.count)

            artifact_name = "TSK_" + 'inventory_application_file_virustotal_scan'.upper()
            artifact_desc = "Amcache " + 'inventory_application_file_virustotal_scan'.upper()

            try:
                self.log(Level.INFO, "Begin creating inventory_application_file_virustotal_scan Artifacts")
                artID_amc = skCase.addArtifactType(artifact_name, artifact_desc)
            except:        
                self.log(Level.INFO, "ARTIFACTS CREATION ERROR: inventory_application_file_virustotal_scan")

            artID_typeID = skCase.getArtifactTypeID(artifact_name)
            artID_type = skCase.getArtifactType(artifact_name)

            # start scanning 'inventory_application_file' SHA1 hashes
            for i in range(0, self.inventory_application_file_count):
                subprocess.Popen([self.my_exe,'-d', mydb, '-a', self.API_Key, '-t', 'inventory_application_file', '-k', str(i + 1)]).communicate()[0]
                try: 
                    Class.forName("org.sqlite.JDBC").newInstance()
                    dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % mydb)
                except SQLException as e:
                    self.log(Level.INFO, "Could not open database file (not SQLite) " + mydb + " (" + e.getMessage() + ")")
                    return IngestModule.ProcessResult.OK

                if i == 0:
                    try:
                        stmt = dbConn.createStatement()
                        resultSet = stmt.executeQuery('SELECT COUNT(*) as count FROM sqlite_master WHERE type = "table" AND name = "inventory_application_file_virustotal_scan";')
                        self.log(Level.INFO, "query SQLite Master table for inventory_application_file_virustotal_scan")
                    except SQLException as e:
                       self.log(Level.INFO, "Error querying database for table inventory_application_file_virustotal_scan (" + e.getMessage() + ")")
                    if int(resultSet.getString("count")):
                        self.log(Level.INFO, "inventory_application_file_virustotal_scan found")
                        for j in range(0,len(Column_Names)):
                            if Column_Types[j].upper() == "TEXT":
                                try:
                                    attID_ex1 = skCase.addArtifactAttributeType("TSK_" + Column_Names[j].upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, Column_Names[j])
                                except:        
                                    self.log(Level.INFO, "Attributes Creation Error, " + Column_Names[j] + " ==> ")
                            else:
                                try:
                                    attID_ex1 = skCase.addArtifactAttributeType("TSK_" + Column_Names[j].upper(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, Column_Names[j])
                                except:        
                                    self.log(Level.INFO, "Attributes Creation Error, " + Column_Names[j] + " ==> ")
                    stmt.close()

                SQL_String_1 = 'SELECT "p_key","file","sha1","vt_positives","vt_ratio","vt_report_link" from "inventory_application_file_virustotal_scan" WHERE p_key = ' + str(i + 1) + ';'
                stmt = dbConn.createStatement()
                resultSet3 = stmt.executeQuery(SQL_String_1)
                while resultSet3.next():
                    art = file.newArtifact(artID_typeID)
                    Column_Number = 1
                    for col_name in Column_Names:
                        c_name = "TSK_" + col_name.upper()
                        attID_ex1 = skCase.getAttributeType(c_name)
                        if Column_Types[Column_Number - 1].upper() == "TEXT":
		                    art.addAttribute(BlackboardAttribute(attID_ex1, AmcacheScanIngestModuleFactory.moduleName, resultSet3.getString(col_name)))
                        elif Column_Types[Column_Number - 1] == "":
                            art.addAttribute(BlackboardAttribute(attID_ex1, AmcacheScanIngestModuleFactory.moduleName, resultSet3.getString(col_name)))
                        else:
                            art.addAttribute(BlackboardAttribute(attID_ex1, AmcacheScanIngestModuleFactory.moduleName, long(resultSet3.getInt(col_name))))
                        Column_Number = Column_Number + 1
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(AmcacheScanIngestModuleFactory.moduleName, artID_type, None))
                stmt.close()
                dbConn.close()

                if not self.Private:
                    after_time = time.time()
                    diff = current_time - after_time
                    time.sleep(15 - diff)
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK
                    current_time = time.time()
                self.count += 1
                progressBar.progress(self.count)
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Amcache Scan", " VirusTotal Scan Complete " ) 
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK                


# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class AmcacheScanWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.API_Key = ""
        self.API_Key_Type = False 

    def getVersionNumber(self):
        return serialVersionUID

    # Define getters and settings for data you want to store from UI
    def getAPI_Key(self):
        return self.API_Key

    def setAPI_Key(self, flag):
        self.API_Key = flag

    def getPrivate(self):
        return self.Private

    def setPrivate(self, flag):
        self.Private = flag

# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class AmcacheScanWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'
    
    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    # TODO: Update this for your UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()
    
    # Check the checkboxs to see what actions need to be taken
    def checkBoxEvent(self, event):
        if self.Private_API_Key_CB.isSelected():
            self.local_settings.setPrivate(True)
            self.local_settings.setAPI_Key(self.API_Key_TF.getText())
        else:
            self.local_settings.setPrivate(False)
            self.local_settings.setAPI_Key(self.API_Key_TF.getText())

    # Check to see if there are any entries that need to be populated from the database.        
    def check_Database_entries(self):
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\GUI_Settings.db3"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings DB!")
 
        try:
            stmt = dbConn.createStatement()
            SQL_Statement = 'Select Setting_Name, Setting_Value from settings;' 
            resultSet = stmt.executeQuery(SQL_Statement)
            while resultSet.next():
                if resultSet.getString("Setting_Name") == "API_Key":
                    self.local_settings.setAPI_Key(resultSet.getString("Setting_Value"))
                    self.API_Key_TF.setText(resultSet.getString("Setting_Value"))
                if resultSet.getString("Setting_Name") == "Private":
                    private = resultSet.getString("Setting_Value")
                    if private == "1":
                        self.local_settings.setPrivate(True)
                    else:
                        self.local_settings.setPrivate(False)

            self.Error_Message.setText("Settings Read successfully!")
        except SQLException as e:
            self.Error_Message.setText("Error Reading Settings Database")

        stmt.close()
        dbConn.close()

    # Save entries from the GUI to the database.
    def SaveSettings(self, e):
        
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\GUI_Settings.db3"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings")

        try:
            stmt = dbConn.createStatement()
            SQL_Statement = 'UPDATE settings SET Setting_Value = "' + self.API_Key_TF.getText() + '" WHERE Setting_Name = "API_Key";'
            resultSet = stmt.executeQuery(SQL_Statement)
        except:
            pass
        try:
            if self.local_settings.getPrivate():
                SQL_Statement = 'UPDATE settings SET Setting_Value = "1" WHERE Setting_Name = "Private";' 
                resultSet = stmt.executeQuery(SQL_Statement)
            else:
                SQL_Statement = 'UPDATE settings SET Setting_Value = "0" WHERE Setting_Name = "Private";'  
                resultSet = stmt.executeQuery(SQL_Statement)
        except:
            pass

        self.Error_Message.setText("Settings Saved")
        stmt.close()
        dbConn.close()


    # Create the initial data fields/layout in the UI
    def initComponents(self):
        self.panel0 = JPanel()

        self.rbgPanel0 = ButtonGroup() 
        self.gbPanel0 = GridBagLayout() 
        self.gbcPanel0 = GridBagConstraints() 
        self.panel0.setLayout( self.gbPanel0 ) 

        self.LabelA = JLabel("VirusTotal API Key:")
        self.LabelA.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 1 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.LabelA, self.gbcPanel0 ) 
        self.panel0.add( self.LabelA ) 

        self.API_Key_TF = JTextField(20) 
        self.API_Key_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.API_Key_TF, self.gbcPanel0 ) 
        self.panel0.add( self.API_Key_TF ) 

        self.Blank_1 = JLabel( " ") 
        self.Blank_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 6
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_1, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_1 ) 

        self.Private_API_Key_CB = JCheckBox("Private API Key?", actionPerformed=self.checkBoxEvent)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Private_API_Key_CB, self.gbcPanel0 ) 
        self.panel0.add( self.Private_API_Key_CB )

        self.Save_Settings_BTN = JButton( "Save Settings", actionPerformed=self.SaveSettings) 
        self.Save_Settings_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Save_Settings_BTN ) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 8
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Save_Settings_BTN, self.gbcPanel0 ) 
        self.panel0.add( self.Save_Settings_BTN ) 

        self.Label_1 = JLabel( "Error Message:") 
        self.Label_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Label_1, self.gbcPanel0 ) 
        self.panel0.add( self.Label_1 ) 

        self.Error_Message = JLabel( "") 
        self.Error_Message.setEnabled(True)
        self.gbcPanel0.gridx = 6
        self.gbcPanel0.gridy = 11
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH
        self.gbPanel0.setConstraints( self.Error_Message, self.gbcPanel0 ) 
        self.panel0.add( self.Error_Message ) 

        self.add(self.panel0)

    # Custom load any data field and initialize the values
    def customizeComponents(self):
        self.check_Database_entries()
        self.Private_API_Key_CB.setSelected(self.local_settings.getPrivate())

    # Return the settings used
    def getSettings(self):
        return self.local_settings

