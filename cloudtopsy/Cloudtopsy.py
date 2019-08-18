

import jarray
import inspect
import os
import subprocess
import time
import re

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
class CloudtopsyIngestModuleFactory(IngestModuleFactoryAdapter):

    def __init__(self):
        self.settings = None

    moduleName = "Cloudtopsy"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Download and ingest CloudTrail logs from AWS"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def getDefaultIngestJobSettings(self):
        return CloudtopsyWithUISettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, CloudtopsyWithUISettings):
            raise IllegalArgumentException("Expected settings argument to be instanceof SampleIngestModuleSettings")
        self.settings = settings
        return CloudtopsyWithUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return CloudtopsyIngestModule(self.settings)

# Data Source-level ingest module.  One gets created per data source.
class CloudtopsyIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(CloudtopsyIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.List_Of_tables = [] 

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context
        self.Access_Key = self.local_settings.getAccessKey()
        self.Secret_Key = self.local_settings.getSecretKey()
        self.Region = self.local_settings.getRegion()
        self.Bucket = self.local_settings.getBucket()

        #Record Parameters
        self.log(Level.INFO, "Bucket: " + str(self.Bucket))
        self.log(Level.INFO, "Access_Key: " + str(self.Access_Key))
        self.log(Level.INFO, "Secret Key: " + str(self.Secret_Key))
        self.log(Level.INFO, "Region: " + str(self.Region))

        self.my_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cloudtopsy.exe")
        if not os.path.exists(self.my_exe):
            raise IngestModuleException("EXE was not found in module folder")

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See:x http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar): 

        # Check if this is Windows
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO, "Ignoring data source.  Not running on Windows")
            return IngestModule.ProcessResult.OK
        
        progressBar.switchToIndeterminate()
        
        skCase = Case.getCurrentCase().getSleuthkitCase();
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        
        # In most Autopsy plugins this is where, the plugins searches for the files it's going to parse (i.e. a Registry hive or Log file)
        # In this plugin the data were adding to the case comes from outside autopsy, so there isn't really a file to associate the output with
        # but Autopsy expects the artifacts produced by the plugin to be associated with a file 
        # So, this plugin just selects the very first file in the dataset, and associates the artifacts with that.
        files = fileManager.findFiles(dataSource, "%")
        self.log(Level.INFO, "CloudTrail logs will be associated with " + files[0].getName())
  
  
        Temp_Dir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "Found temporary directory: " + Temp_Dir)

       
        mydb = Temp_Dir + "\\Cloudtopsy.db"
        # Parse some keys
        self.log(Level.INFO, "Downloading and parsing CloudTrail logs: \"" + self.my_exe + "\" -a \"" + self.Access_Key + "\" -s \"" + self.Secret_Key + "\" -r \"" + self.Region + "\" -b \"" + self.Bucket + "\" -d \"" + mydb + "\"")
        subprocess.Popen([self.my_exe, '-a', self.Access_Key, '-s', self.Secret_Key, '-r', self.Region, '-b', self.Bucket, '-d', mydb]).communicate()[0] 

        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % mydb)
        except SQLException as e:
            self.log(Level.INFO, "Could not open database file " + mydb + " (" + e.getMessage() + ")")
            return IngestModule.ProcessResult.OK
             

        # Retrieve a list of CloudTrail APIs called 
        try:
            stmt = dbConn.createStatement()
            tableSet = stmt.executeQuery("SELECT name from sqlite_master WHERE type='table' ORDER by name; ")
            self.log(Level.INFO, "SQLite Query: SELECT name from sqlite_master WHERE type='table' ORDER by name;")
        except SQLException as e:
            self.log(Level.INFO, "Error Running Query: SELECT name from sqlite_master WHERE type='table' ORDER by name;")
            return IngestModule.ProcessResult.OK
        while tableSet.next(): 
            self.List_Of_tables.append(tableSet.getString("name"))
          
        # Retrieve a count of CloudTrail APIs called and use it for the Progress Bar  
        try:
            stmt = dbConn.createStatement()
            resultSet = stmt.executeQuery("SELECT COUNT(*) as count FROM Sqlite_Master WHERE type='table'; ")
            self.log(Level.INFO, "SELECT COUNT(*) as count FROM Sqlite_Master WHERE type='table';")
        except SQLException as e:
            self.log(Level.INFO, "SELECT COUNT(*) as count FROM Sqlite_Master WHERE type='table';")
            return IngestModule.ProcessResult.OK   
        progressBar.switchToDeterminate(int(resultSet.getString("count")))
        
        stmt.close()
        dbConn.close()
        
        
        # Ingest the tables that have already been created in mydb in Autopsy
        count = 0
        for table_name in self.List_Of_tables:
            SQL_String_1 = "Select * from " + table_name + ";"
            SQL_String_2 = "PRAGMA table_info('" + table_name + "')"
            artifact_name = "TSK_" + table_name.upper()
            artifact_desc = "CloudTrail: " + table_name.upper()

            artID_amc = skCase.addArtifactType(artifact_name, artifact_desc)
            artID_amc = skCase.getArtifactTypeID(artifact_name)
            artID_amc_evt = skCase.getArtifactType(artifact_name)
            
            try:
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % mydb)
                stmt = dbConn.createStatement()
            except SQLException as e:
                return IngestModule.ProcessResult.OK
                       
            Column_Names = []
            Column_Types = []
            self.log(Level.INFO, "Running Query: " + SQL_String_2)
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

            self.log(Level.INFO, "Running Query: " + SQL_String_1)                                
            resultSet3 = stmt.executeQuery(SQL_String_1)
            while resultSet3.next():
                art = files[0].newArtifact(artID_amc)
                Column_Number = 1
                for col_name in Column_Names:  
                    c_name = "TSK_" + col_name
                    attID_ex1 = skCase.getAttributeType(c_name)
                    if Column_Types[Column_Number - 1] == "TEXT":
                        art.addAttribute(BlackboardAttribute(attID_ex1, CloudtopsyIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                    elif Column_Types[Column_Number - 1] == "":
                        art.addAttribute(BlackboardAttribute(attID_ex1, CloudtopsyIngestModuleFactory.moduleName, resultSet3.getString(Column_Number)))
                    else:
                        art.addAttribute(BlackboardAttribute(attID_ex1, CloudtopsyIngestModuleFactory.moduleName, long(resultSet3.getInt(Column_Number))))
                    Column_Number = Column_Number + 1
            
            IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(CloudtopsyIngestModuleFactory.moduleName, artID_amc_evt, None))
            stmt.close()
            dbConn.close()
            count += 1
            progressBar.progress(count)              
                   


        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "Cloudtopsy", " CloudTrail Logs Successfully Ingested!" ) 
        IngestServices.getInstance().postMessage(message)
        return IngestModule.ProcessResult.OK
        


# Stores the settings that can be changed for each ingest job
# All fields in here must be serializable.  It will be written to disk.
# TODO: Rename this class
class CloudtopsyWithUISettings(IngestModuleIngestJobSettings):
    serialVersionUID = 1L

    def __init__(self):
        self.Access_Key = ""
        self.Secret_Key = ""
        self.Region = ""
        self.Bucket = ""

    def getVersionNumber(self):
        return serialVersionUID

    # Define getters and settings for data you want to store from UI
    def getAccessKey(self):
        return self.Access_Key

    def setAccessKey(self, data):
        self.Access_Key = data

    def getSecretKey(self):
        return self.Secret_Key

    def setSecretKey(self, data):
        self.Secret_Key = data

    def getRegion(self):
        return self.Region

    def setRegion(self, data):
        self.Region = data
        
    def getBucket(self):
        return self.Bucket

    def setBucket(self, data):
        self.Bucket = data
        
# UI that is shown to user for each ingest job so they can configure the job.
# TODO: Rename this
class CloudtopsyWithUISettingsPanel(IngestModuleIngestJobSettingsPanel):
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
    
    # Check to see if there are any entries that need to be populated from the database.        
    def check_Database_entries(self):
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\config.db"
        
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings DB!")
                
        if os.path.exists(settings_db):
     
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = 'Select Key_Name, Key_Value from CONFIG;' 
                resultSet = stmt.executeQuery(SQL_Statement)
                while resultSet.next():
                    if resultSet.getString("Key_Name") == "BUCKET":
                        self.local_settings.setBucket(resultSet.getString("Key_Value"))
                        self.Bucket_TF.setText(resultSet.getString("Key_Value"))
                    if resultSet.getString("Key_Name") == "ACCESS_KEY":
                        self.local_settings.setAccessKey(resultSet.getString("Key_Value"))
                        self.Access_Key_TF.setText(resultSet.getString("Key_Value"))
                    if resultSet.getString("Key_Name") == "SECRET_KEY":
                        self.local_settings.setSecretKey(resultSet.getString("Key_Value"))
                        self.Secret_Key_TF.setText(resultSet.getString("Key_Value"))
                    if resultSet.getString("Key_Name") == "AWS_REGION":
                        self.local_settings.setRegion(resultSet.getString("Key_Value"))
                        self.Region_TF.setText(resultSet.getString("Key_Value"))
                self.Error_Message.setText("Settings Read successfully!")
            except SQLException as e:
                self.Error_Message.setText("Error Reading Settings Database")
        
        else:
            
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = 'CREATE TABLE CONFIG ( Setting_Name Text, Setting_Value Text)' 
                resultSet = stmt.executeQuery(SQL_Statement)
            except SQLException as e:
                self.Error_Message.setText("Error Creating Settings Database")
            

        stmt.close()
        dbConn.close()

    # Save entries from the GUI to the database.
    def SaveSettings(self, e):
        error = False
        head, tail = os.path.split(os.path.abspath(__file__)) 
        head, tail = os.path.split(os.path.abspath(__file__)) 
        settings_db = head + "\\config.db"
        try: 
            Class.forName("org.sqlite.JDBC").newInstance()
            dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % settings_db)
        except SQLException as e:
            self.Error_Message.setText("Error Opening Settings")

        try:
            stmt = dbConn.createStatement()
            SQL_Statement = 'UPDATE CONFIG SET Key_Value = "' + self.Bucket_TF.getText() + '" WHERE Key_Name = "BUCKET";'
            resultSet = stmt.executeQuery(SQL_Statement)
        except:
            pass

        if re.match(r'[A-Z0-9]{20}', self.Access_Key_TF.getText()):
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = 'UPDATE CONFIG SET Key_Value = "' + self.Access_Key_TF.getText() + '" WHERE Key_Name = "ACCESS_KEY";'
                resultSet = stmt.executeQuery(SQL_Statement)
            except:
                pass
        else: 
            error = True
            self.Error_Message.setText("Access Key Invalid")
        
        if re.match(r'[A-Za-z0-9/+=]{40}', self.Secret_Key_TF.getText()):
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = 'UPDATE CONFIG SET Key_Value = "' + self.Secret_Key_TF.getText() + '" WHERE Key_Name = "SECRET_KEY";'
                resultSet = stmt.executeQuery(SQL_Statement)
            except:
                pass
        else:
            error = True
            self.Error_Message.setText("Secret Key Invalid")
        
        if re.match(r'[a-z]{2}-(gov-)?(north|south|east|west|central)(east|west)?-\d(\w)?', self.Region_TF.getText()): 
            try:
                stmt = dbConn.createStatement()
                SQL_Statement = 'UPDATE CONFIG SET Key_Value = "' + self.Region_TF.getText() + '" WHERE Key_Name = "AWS_REGION";'
                resultSet = stmt.executeQuery(SQL_Statement)
            except:
                pass
        else: 
            error = True
            self.Error_Message.setText("AWS Region Invalid")
            
        if not error:
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
        
        self.LabelA = JLabel("S3 Bucket:")
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

        self.Bucket_TF = JTextField(20) 
        self.Bucket_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 3 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Bucket_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Bucket_TF ) 

        self.Blank_1 = JLabel( " ") 
        self.Blank_1.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 4
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_1, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_1 ) 
        
        self.LabelB = JLabel("AWS Access Key:")
        self.LabelB.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 5 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.LabelB, self.gbcPanel0 ) 
        self.panel0.add( self.LabelB ) 

        self.Access_Key_TF = JTextField(20) 
        self.Access_Key_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 7 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Access_Key_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Access_Key_TF ) 

        self.Blank_2 = JLabel( " ") 
        self.Blank_2.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 8
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_2, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_2 ) 
        
        self.LabelC = JLabel("AWS Secret Key:")
        self.LabelC.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 9 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.LabelC, self.gbcPanel0 ) 
        self.panel0.add( self.LabelC ) 

        self.Secret_Key_TF = JTextField(20) 
        self.Secret_Key_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 11 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Secret_Key_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Secret_Key_TF ) 

        self.Blank_3 = JLabel( " ") 
        self.Blank_3.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 12
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_3, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_3 ) 
        
        self.LabelD = JLabel("AWS Region:")
        self.LabelD.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 13
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.LabelD, self.gbcPanel0 ) 
        self.panel0.add( self.LabelD ) 

        self.Region_TF = JTextField(20) 
        self.Region_TF.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 15 
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Region_TF, self.gbcPanel0 ) 
        self.panel0.add( self.Region_TF ) 
    
        self.Blank_4 = JLabel( " ") 
        self.Blank_4.setEnabled(True)
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 16
        self.gbcPanel0.gridwidth = 1 
        self.gbcPanel0.gridheight = 1 
        self.gbcPanel0.fill = GridBagConstraints.BOTH 
        self.gbcPanel0.weightx = 1 
        self.gbcPanel0.weighty = 0 
        self.gbcPanel0.anchor = GridBagConstraints.NORTH 
        self.gbPanel0.setConstraints( self.Blank_4, self.gbcPanel0 ) 
        self.panel0.add( self.Blank_4 ) 


        self.Save_Settings_BTN = JButton( "Save Settings", actionPerformed=self.SaveSettings) 
        self.Save_Settings_BTN.setEnabled(True)
        self.rbgPanel0.add( self.Save_Settings_BTN ) 
        self.gbcPanel0.gridx = 2 
        self.gbcPanel0.gridy = 17
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
        self.gbcPanel0.gridy = 18
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
        self.gbcPanel0.gridy = 19
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

    # Return the settings used
    def getSettings(self):
        return self.local_settings

