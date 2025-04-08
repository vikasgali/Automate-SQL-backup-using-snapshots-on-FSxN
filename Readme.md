This script wil automate the T-SQL backup flow utilizing snapshots on FSx for ONTAP filesystem and TSQL suspend and metadata backup. This will replace the
full and incremental backups of SQL. Recommended to run every 6hrs or at desired frequency. Transaction log backups would continue in the traditional way 
more frequently at 15min or lesser as needed.
The script fetches the disks assigned to SQL instance/databases and maps that back to LUN and volume on FSx for ONTAP. 

# Pre-requisites: 

The PowerShell script can be run at required schedule using SQL agent or Windows scheduler. Some of the pre-requisites are as below
1. The script expects the FSx credentails to be saved as AWS SSM parameter as a secure way of storing and retreiving credentials. 
	a. Create a parameter of type 'Secure String' with name as '/tsql/filesystem/<FSxN filesystem ID>'
	b. For value enter the fsx credentials in JSON format as {fsx:{username:'fsxadmin',password:'password'}}
2. AWS.Tools.SimpleSystemsManagement PowerShell module needs to be installed on the system where script is running.

# Usage:

# To run backup on a single database:

TSQL_Backup.ps1 -FSxID <FSx filesystem ID> -FSxRegion <AWS region> -serverInstanceName <SQL Server instance name> -databaseName <database name>

Example:

TSQL_Backup.ps1 -FSxID 'fs-07a22f282fd4f5a20' -FSxRegion 'eu-south-2' -serverInstanceName 'MSSQLSERVER'-databaseName 'Finance'

TSQL_Backup.ps1 -FSxID 'fs-07a22f282fd4f5a20' -FSxRegion 'eu-south-2' -serverInstanceName 'ENGINEERING' -databaseName 'Payments'

# To run backup on a group of databases:

TSQL_Backup.ps1 -FSxID <FSx filesystem ID> -FSxRegion <AWS region> -serverInstanceName <SQL Server instance name> -databaseName <comma-separated database names>

Example:

TSQL_Backup.ps1 -FSxID 'fs-07a22f282fd4f5a20' -FSxRegion 'eu-south-2' -serverInstanceName 'ENGINEERING' -databaseName 'Finance,Resources,Accounts'

# To run backup on a Server(all databases):

TSQL_Backup.ps1 -FSxID <FSx filesystem ID> -FSxRegion <AWS region> -serverInstanceName <SQL Server instance name>

Example:

TSQL_Backup.ps1 -FSxID 'fs-07a22f282fd4f5a20' -FSxRegion 'eu-south-2' -serverInstanceName 'ENGINEERING'
