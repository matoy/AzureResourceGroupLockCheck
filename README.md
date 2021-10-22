# AzureResourceGroupLockCheck
  
## Why this function app ?
Azure provides "lock" feature on resources, including on resource groups.  
  
It can be a good practice do have locks in place on your resource groups to protect from mistakes.  
  
This function app automatically checks if resource groups of a specified subscription are locked or not.  
  
You can also specify exception if you explicitely don't want to check lock for some resource groups or specify that want to check for a readonly lock instead of a delete lock.  
  
Coupled with a common monitoring system (nagios, centreon, zabbix, or whatever you use), you'll automatically get alerted as soon as a resource group is not locked as it should be.  
</br>
</br>

## Requirements
* An "app registration" account (client id, valid secret and tenant id).  
* Reader RBAC role for this account on all subscriptions you want to monitor.  


## Installation
Once you have all the requirements, you can deploy the Azure function with de "Deploy" button below:  
  
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmatoy%2FAzureResourceGroupLockCheck%2Fmain%2Farm-template%2FAzureResourceGroupLockCheck.json) [![alt text](http://armviz.io/visualizebutton.png)](http://armviz.io/#/?load=https://raw.githubusercontent.com/matoy/AzureResourceGroupLockCheck/main/arm-template/AzureResourceGroupLockCheck.json)  
  
</br>
This will deploy an Azure app function with its storage account, app insights and "consumption" app plan.  
A keyvault will also be deployed to securely store the secret of your app principal.  
  
![alt text](https://github.com/matoy/AzureResourceGroupLockCheck/blob/main/img/screenshot1.png?raw=true)  
  
Choose you Azure subscription, region and create or select a resource group.  
  
* App Name:  
You can customize a name for resources that will be created.  
  
* Tenant ID:  
If your subscription depends on the same tenant than the account used to retrieve subscriptions information, then you can use the default value.  
Otherwise, enter the tenant ID of the account.  
  
* Subscription Reader Application ID:  
Client ID of the account used to retrieve subscriptions information.  
  
* Subscription Reader Secret:  
Secret of the account used to retrieve subscriptions information.  
   
* Zip Release URL:  
For testing, you can leave it like it.  
For more serious use, I would advise you host your own zip file so that you wouldn't be subject to release changes done in this repository.  
See below for more details.  
  
* Max Concurrent Jobs:  
An API call to Azure will be made for each subscription.  
If you have many subscription, you might get an http timeout when calling the function from your monitoring system.  
This value allows to make <value> calls to Azure API in parallel.  
With the default value, it will take around 30 seconds for ~100 subscriptions.  
  
* Global Exceptions:  
There are some Azure internal resource groups that you might not want to check like NetworkWatcherRG, etc.  
You can specify comma separated names.  
  
* Signature:  
When this function will be called by your monitoring system, you likely might forget about it.  
The signature output will act a reminder since you'll get it in the results to your monitoring system.  
  
</br>
When deployment is done, you can get your Azure function's URL in the output variables.  
  
Trigger it manually in your favorite browser and eventually look at the logs in the function.  
  
After you execute the function for the first time, it might (will) need 5-10 minutes before it works because it has to install Az module. You even might get an HTTP 500 error. Give the function some time to initialize, re-execute it again if necessary and be patient, it will work.  
  
Even after that, you might experience issue if Azure takes time to resolve your newly created keyvault:  
![alt text](https://github.com/matoy/AzureResourceGroupLockCheck/blob/main/img/kv-down.png?raw=true)  
Wait a short time and then restart your Azure function, your should have something like:  
![alt text](https://github.com/matoy/AzureResourceGroupLockCheck/blob/main/img/kv-up.png?raw=true)  
</br>
</br>

## Monitoring integration  
From there, you just have to call your function's URL from your monitoring system.  
  
You can find a script example in "monitoring-script-example" folder which makes a GET request, outputs the result, looks for "CRITICAL" or "WARNING" in the text and use the right exit code accordingly.  
  
Calling the function once a day should be enough.  
  
You have make 1 function call per subscription by specifying the subscriptionid in the GET parameters: &subscriptionid=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  
  
You can also specify comma separated resource group names to exclude with &exclusions=rg1,rg2  
  
Or check for a readonly lock instead of delete lock with comma separated resource group names with &readonly=rg3,rg4  
  
Be sure to have an appropriate timeout (60s or more) because if you have many subscriptions, the function will need some time to execute.  
  
This is an example of what you'd get in Centreon:  
![alt text](https://github.com/matoy/AzureResourceGroupLockCheck/blob/main/img/screenshot2.png?raw=true)  
</br>
</br>

## How to stop relying on this repository's zip  
To make your function to stop relying on this repo's zip and become independant, follow these steps:  
* remove zipReleaseURL app setting and restart app  
* in "App files" section, edit "requirements.psd1" and uncomment the line: 'Az' = '6.*'  
* in "Functions" section, add a new function called "AzureResourceGroupLockCheck" and paste in it the content of the file release/AzureResourceGroupLockCheck/run.ps1 in this repository  
