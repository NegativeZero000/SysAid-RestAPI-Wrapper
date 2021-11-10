$script:SysAidAPIPaths = @{
    root = "api/v1/"
    Users = "users"
    SpecificUser = "users/{0}"
    Login = "login"
    SearchUsers = "users/search"
    NewServiceRequest = "sr"
    CloseServiceRequest = "sr/{0}/close"
    AddServiceRequestLink = "sr/{0}/link"
    GetServiceRequestList = "sr"
    GetServiceRequest = "sr/{0}"
    UpdateServiceRequest = "sr/{0}"
    GetServiceRecordTemplate = "sr/template"
    GetList = "list/{0}"
    GetAllLists = "list"
    AddServiceRequestAttachment = "sr/{0}/attachment"
}

$script:SysAidAPIErrors = @{
    ServiceRequestAlreadyClosed = "This service record is already closed."
}

function ConvertTo-SysAidFriendlyText{
    # There are several characters that will be rejected by the API and trigger HTML 500 Errors
    # This function will address those
    param($string)
    # return ($string -replace [char]0xA0 -replace [char]0x2013, "-")
    if($string){return [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($string))}
}

function Get-SysAidTenantURL{
    return $script:sysAidTenantURL
}

function Get-SysAidWebSession{
    return $script:sysAidWebSession
}

function Get-FileContentType{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.IO.FileInfo]$File,

        [Parameter(Mandatory=$false)]
        [string]$Default = "application/octet-stream"
    )

    Add-Type -AssemblyName System.Web
    if($mimeMapping = [System.Web.MimeMapping]::GetMimeMapping($File)){
        return $mimeMapping
    } else {
        return $Default
    }
}

function Get-SysAidErrorMessage{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.CmdletInvocationException]$ErrorObject,

        [Parameter(Mandatory=$false)]
        [uri]$URL,

        [Parameter(Mandatory=$false)]
        [string]$RequestBody
    )

    Write-Verbose $ErrorObject
    # Check if JSON response is in the error
    try{
        $errorDetails = $ErrorObject.Message | ConvertFrom-Json -ErrorAction Stop
    } catch [ArgumentException]{
        Write-Verbose "This is not a JSON compatible error. Attempt to parse manually"
    }
    $message = [System.Collections.ArrayList ]

    if($errorDetails){
        $message = "<Http Status Code>: {0} `r`n<Http Status Description>: '{1}'" -f $errorDetails.Status, $errorDetails.Message
    } else {
        $message = "Http Status Code: {0} `r`nHttp Status Description>: '{1}'" -f [int]$ErrorObject.InnerException.response.statuscode, ($ErrorObject.ToString() | Out-string)
    }

    if($URL){$message = $message + "`r`n<URL>: {0}" -f $URL.AbsoluteUri}
    if($RequestBody){$message = $message + "`r`n<Request Body>: {0}" -f $RequestBody}

    return $message
}

function Set-SysAidAPIWebSession{
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [string]$TenantURL,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credentials
    )

    $invokeWebRequestLoginParameters = @{
        URI = $TenantURL + $SysAidAPIPaths.root + $SysAidAPIPaths.login
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Post
        ContentType = "application/json"
        Body = @{
            user_name = $Credentials.UserName
            password = $Credentials.GetNetworkCredential().password
        } | ConvertTo-Json
        ErrorVariable = "invokeWebRequestError"
        SessionVariable = "session"
    }
    
    # Authenticate to SysAid tenant and return websession
    try{
        Invoke-WebRequest @invokeWebRequestLoginParameters | Out-Null
    } catch [InvalidOperationException]{
        throw (Get-SysAidErrorMessage -ErrorObject $invokeWebRequestError[0])
    }
    
    $script:sysAidWebSession = $session
    $script:sysAidTenantURL = $tenantURL
}

function Get-SysAidUser{
    [CmdletBinding(DefaultParameterSetName="Some")]
    param (
        [Parameter(Mandatory=$false)]
        [string]$View,

        [Parameter(Mandatory=$false)]
        [string[]]$Fields=@(),

        [Parameter(Mandatory=$false)]
        [int]$Offset=0,

        [Parameter( Mandatory=$false)]
        [ValidateRange(1,500)]
        [int]$Limit=500,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Admin","User","Manager")]
        [string]$Type="User",

        [Parameter(ParameterSetName="All")]
        [switch]$All=$false,

        [Parameter(ParameterSetName="ID", Mandatory=$true)]
        [int]$ID
    )

    if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}

    # Build the query string using the supplied parameters where applicable
    $queryParameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty) 
    if($Type){$queryParameters.Add("type",$Type.ToLower())}
    if($View){$queryParameters.Add("view",$View)}
    if($Fields){$queryParameters.Add("fields",$Fields -join ",")}
    if($Offset){$queryParameters.Add("offset",$Offset)}
    if($Limit){$queryParameters.Add("limit",$Limit)}

    # Set the URI based on the parameter set
    Switch($pscmdlet.ParameterSetName){
        "ID"{$completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + ($SysAidAPIPaths.SpecificUser -f $ID))}
        default{$completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + $SysAidAPIPaths.Users)}
    }
    $completeURI.Query = $queryParameters.ToString()

    $invokeRestMethodGetUserParameters = @{
        URI = $completeURI.Uri.AbsoluteUri
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
        ContentType = "application/json"
        ErrorVariable = "invokeRestMethodError"
        WebSession = $script:sysAidWebSession 
    }

    # Execute the request
    try{
        $response = Invoke-RestMethod @invokeRestMethodGetUserParameters
    } catch [InvalidOperationException]{
        if ($invokeRestMethodError){
            throw (Get-SysAidErrorMessage -ErrorObject $invokeRestMethodError[0])
        }
    }

    # Return the results, if any, and call again if we suspect there is more
    if($response){
        if($response.count -eq $Limit -and $pscmdlet.ParameterSetName -eq "All"){
            $getSysAidUserParameters = @{
                View = $View
                Fields = $Fields
                Offset = $Offset + $Limit
                Limit = $Limit
                Type = $Type
                All = $true
            }
            Get-SysAidUser @getSysAidUserParameters 
        }
        return $response
    }
}

function New-SysAidServiceRequestNote{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$False)]
        [string]$SubmitUserName,

        [Parameter(Mandatory=$False)]
        [datetime]$CreateDate = (Get-Date),

        [Parameter(Mandatory=$False)]
        [string]$Text = ""
    )

    return [PSCustomObject]@{
        userName = $SubmitUserName
        createDate = ConvertTo-UnixEpochTime $CreateDate
        # Remove any non-breaking spaces from the text
        # Replace emdash with regular dash
        text = ConvertTo-SysAidFriendlyText $Text
    }
}

function ConvertTo-UnixEpochTime{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [datetime]$Date
    )
    $unixEpochStart = [DateTime]::new(1970,1,1,0,0,0,([DateTimeKind]::Utc))
    [int64]($Date.ToUniversalTime() - $unixEpochStart).TotalMilliseconds
}

function New-SysAidServiceRecordPayload{
    [CmdletBinding(DefaultParameterSetName="New")]
    param (
        [Parameter(Mandatory=$True,ParameterSetName="Update")]
        [int]$ID,

        [Parameter(Mandatory=$False)]
        [string]$Category,

        [Parameter(Mandatory=$False)]
        [string]$SubCategory,

        [Parameter(Mandatory=$False)]
        [string]$ThirdLevelCategory,

        [Parameter(Mandatory=$False)]
        [string]$Title,

        [Parameter(Mandatory=$False)]
        [string]$Description,

        [Parameter(Mandatory=$False)]
        [int]$Status,

        [Parameter(Mandatory=$False)]
        [datetime]$DueDate,

        [Parameter(Mandatory=$False)]
        [int]$RequestUser,

        [Parameter(Mandatory=$False)]
        [int]$AssignedUser,

        [Parameter(Mandatory=$false)]
        [bool]$Archive,

        [Parameter(Mandatory=$False)]
        [object[]]$Notes,

        [Parameter(Mandatory=$False)]
        [int]$AssignedGroup,

        [Parameter(Mandatory=$False)]
        [System.Collections.Hashtable]$Custom
    )

    $payloadKeyValues = [System.Collections.ArrayList]::new()
    # Add the Categories formatted as one string
    if($Category -and $SubCategory -and $ThirdLevelCategory){
        $categoryString = $Category, $SubCategory, $ThirdLevelCategory -join "_"
    } elseif ($Category -and $SubCategory){
        $categoryString = $Category, $SubCategory -join "_"
    } elseif($Category){
        $categoryString = $Category
    }

    if($categoryString){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "problem_type"
            value = $categoryString
        }) | Out-Null
    }
    # Status integer
    if($status){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "status"
            value = "$Status"
        }) | Out-Null
    }

    # Title
    if($Title){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "title"
            value = ConvertTo-SysAidFriendlyText $Title
        }) | Out-Null
    }

    # Description
    if($Description){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "description"
            value = ConvertTo-SysAidFriendlyText $Description
        }) | Out-Null
    }

    # Date
    if($DueDate){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "due_date"
            value = (ConvertTo-UnixEpochTime $DueDate).ToString()
        }) | Out-Null
    }

    # Request User
    if($RequestUser){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "request_user"
            value = "$RequestUser"
        }) | Out-Null
    }    
    # Assigned User
    if($AssignedUser){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "responsibility"
            value = "$AssignedUser"
        }) | Out-Null
    }

    # Build the notes array
    if($Notes){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "notes"
            value = @($notes)
        }) | Out-Null
    }

    # Build the notes array
    if($Archive){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "archive"
            value = "$([int]$Archive)"
        }) | Out-Null
    }

    # Assigned group
    if($AssignedGroup){
        $payloadKeyValues.Add([PSCustomObject]@{
            key = "assigned_group"
            value = "$AssignedGroup"
        }) | Out-Null
    }
    
    # Add any custom fields not covered by default parameters
    if($Custom){
        $Custom.GetEnumerator() | ForEach-Object{
            $payloadKeyValues.Add([PSCustomObject]@{
                key = $_.Key
                value = [string]$_.value
            }) | Out-Null
        }
    }

    # Payload as an object converted to JSON
    $serviceRecordDetails = @{
        info = $payloadKeyValues
    } 

    # ID depending on the type of payload we are making
    if($PSCmdlet.ParameterSetName -eq "Update"){
        $serviceRecordDetails.id = "$ID"
    }

    return [PSCustomObject]$serviceRecordDetails | ConvertTo-Json -Depth 5
} 

function Get-SysaidServiceRecordTemplate{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$View="",

        [Parameter(Mandatory=$false)]
        [string[]]$Fields=@(),

        [Parameter(Mandatory=$false)]
        [int]$Template=-1,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Incident","Request","Problem","Change")]
        [string]$Type="Incident"
    )

    if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}

    # Build the URI string for creating a new Service Request
    $queryParameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty) 
    $queryParameters.Add("type",$Type.ToLower())
    if($view){$queryParameters.Add("view",$View)}
    if($Fields){$queryParameters.Add("fields",$Fields)}
    if($Template -gt 0){$queryParameters.Add("template",$Template)}

    $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + $SysAidAPIPaths.GetServiceRecordTemplate)
    $completeURI.Query = $queryParameters.ToString()

    # Prepare the splatting variable
    $invokeWebRequestNewServiceRecordsParameters = @{
        URI = $completeURI.Uri.AbsoluteUri
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
        ContentType = "application/json"
        ErrorVariable = "invokeWebRequestError"
        WebSession = $script:sysAidWebSession 
        Body = $Payload
    }

    try{
        $response = $null
        $response = Invoke-RestMethod @invokeWebRequestNewServiceRecordsParameters
    } catch [InvalidOperationException]{
        if ($invokeWebRequestError){
            Write-Error (Get-SysAidErrorMessage -ErrorObject $invokeWebRequestError[0] -URL $invokeWebRequestNewServiceRecordsParameters.URI -RequestBody $invokeWebRequestNewServiceRecordsParameters.Body )
        }
    }

    return $response
}

function Get-SysaidServiceRecordList{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$View,

        [Parameter(Mandatory=$false)]
        [string[]]$Fields=@(),

        [Parameter(Mandatory=$false)]
        [int]$Offset=0,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1,500)]
        [int]$Limit=100,

        [Parameter(Mandatory=$false)]
        [string[]]$Sort,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Asc","Desc")]
        [string]$SortOrder="Asc",

        [Parameter(Mandatory=$false)]
        [ValidateSet("Incident","Request","Problem","Change","All")]
        [string]$Type="All",

        [Parameter(Mandatory=$False)]
        [int[]]$ID
    )
    
    if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}

    # Build the URI string for creating a new Service Request
    $queryParameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty) 
    $queryParameters.Add("type",$Type.ToLower())
    if($view){$queryParameters.Add("view",$View)}
    if($Fields){$queryParameters.Add("fields",($Fields -join ","))}
    if($Offset){$queryParameters.Add("offset",$Offset)}
    if($Limit){$queryParameters.Add("limit",$Limit)}
    if($Sort){
        $queryParameters.Add("sort",($Sort -join ","))
        $queryParameters.Add("dir",$SortOrder.ToLower())
    }
    if($ID){$queryParameters.Add("ids",($ID -join ","))}
    
    $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + $SysAidAPIPaths.GetServiceRequestList)
    $completeURI.Query = $queryParameters.ToString()

        #if($ID.Count -gt 1){Write-Warning "Multiple ID's supplied for a single ID query. Only first ID will be used"}
        #$completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + ($SysAidAPIPaths.GetServiceRequest -f $ID[0]))
    

    # Prepare the splatting variable
    $invokeRestMethodGetServiceRecordsListParameters = @{
        URI = $completeURI.Uri.AbsoluteUri
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
        ContentType = "application/json"
        ErrorVariable = "invokeRestMethodError"
        WebSession = $script:sysAidWebSession 
    }

    try{
        $response = $null
        $response = Invoke-RestMethod @invokeRestMethodGetServiceRecordsListParameters
    } catch [InvalidOperationException]{
        if ($invokeRestMethodError){
            throw (Get-SysAidErrorMessage -ErrorObject $invokeRestMethodError[0])
        }
    }

    return $response
}

function ConvertFrom-SysAidObject{
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [object[]]$Object
    )

    process{
        foreach ($singleObject in $Object){
            foreach($infoTable in $singleObject.info){
                Add-Member -InputObject $singleObject -MemberType NoteProperty -Name $infoTable.key -Value ([PSCustomObject]$infoTable)
            }
            $singleObject
        }
    }
}

function Get-SysaidServiceRecord{
    [CmdletBinding()]
    param (

        [Parameter(Mandatory=$True, ValueFromPipeline=$true)]
        [int]$ID,

        [Parameter(Mandatory=$false)]
        [string]$View,

        [Parameter(Mandatory=$false)]
        [string[]]$Fields=@()
    )

    begin{
        if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}
    
        # Build the URI string for creating a new Service Request
        $queryParameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty) 
        if($view){$queryParameters.Add("view",$View)}
        if($Fields){$queryParameters.Add("fields",($Fields -join ","))}
    }

    process{
        $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + $SysAidAPIPaths.GetServiceRequest -f $ID)
        $completeURI.Query = $queryParameters.ToString()
    
        # Prepare the splatting variable
        $invokeRestMethodGetServiceRecordParameters = @{
            URI = $completeURI.Uri.AbsoluteUri
            Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
            ContentType = "application/json"
            ErrorVariable = "invokeRestMethodError"
            WebSession = $script:sysAidWebSession 
        }
    
        try{
            $response = $null
            $response = Invoke-RestMethod @invokeRestMethodGetServiceRecordParameters
        } catch [InvalidOperationException]{
            if ($invokeRestMethodError){
                throw (Get-SysAidErrorMessage -ErrorObject $invokeRestMethodError[0])
            }
        }
    
        return $response
    }
}

function New-SysAidServiceRecord{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$View="",

        [Parameter(Mandatory=$false)]
        [string[]]$Fields=@(),

        [Parameter(Mandatory=$false)]
        [int]$Template=-1,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Incident","Request","Problem","Change","All")]
        [string]$Type="Incident",

        [Parameter(Mandatory=$True)]
        [string]$Payload
    )
    if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}

    # Build the URI string for creating a new Service Request
    $queryParameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty) 
    $queryParameters.Add("type",$Type.ToLower())
    if($view){$queryParameters.Add("view",$View)}
    if($Fields){$queryParameters.Add("fields",$Fields)}
    if($Template -gt 0){$queryParameters.Add("template",$Template)}

    $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + $SysAidAPIPaths.NewServiceRequest)
    $completeURI.Query = $queryParameters.ToString()

    # Prepare the splatting variable
    $invokeRestMethodNewServiceRecordsParameters = @{
        URI = $completeURI.Uri.AbsoluteUri
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Post
        ContentType = "application/json"
        ErrorVariable = "invokeRestMethodError"
        WebSession = $script:sysAidWebSession 
        Body = $Payload
    }

    try{
        $response = Invoke-RestMethod @invokeRestMethodNewServiceRecordsParameters
    } catch [InvalidOperationException]{
        if ($invokeRestMethodError){
            Write-Error (Get-SysAidErrorMessage -ErrorObject $invokeRestMethodError[0] -URL $invokeRestMethodNewServiceRecordsParameters.URI -RequestBody $invokeRestMethodNewServiceRecordsParameters.Body )
        }
    }

    return $response
}

function Close-SysAidServiceRecord{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [int]$ID,

        [Parameter(Mandatory=$True)]
        [string]$Solution
    )

    if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}

    $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + ($SysAidAPIPaths.CloseServiceRequest -f $ID))

    # Prepare the splatting variable
    $invokeWebRequestCloseServiceRecordsParameters = @{
        URI = $completeURI.Uri.AbsoluteUri
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Put
        ContentType = "application/json"
        ErrorVariable = "invokeWebRequestError"
        WebSession = $script:sysAidWebSession 
        Body = [pscustomobject]@{Solution=$Solution} | ConvertTo-Json
    }

    try{
        $response = $null
        $response = Invoke-WebRequest @invokeWebRequestCloseServiceRecordsParameters
    } catch [InvalidOperationException]{
        if ($invokeWebRequestError[0].Message -match $SysAidAPIErrors.ServiceRequestAlreadyClosed){
            Write-Warning "Service Request $ID is already closed."
        } elseif($invokeWebRequestError){
            throw (Get-SysAidErrorMessage -ErrorObject $invokeWebRequestError[0])
        } 
    }

    return $response
}

function Update-SysAidServiceRecord{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [int]$ID,

        [Parameter(Mandatory=$True)]
        [string]$Payload
    )

    if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}

    $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + ($SysAidAPIPaths.UpdateServiceRequest -f $ID))

    # Prepare the splatting variable
    $invokeRestMethodSetServiceRecordsParameters = @{
        URI = $completeURI.Uri.AbsoluteUri
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Put
        ContentType = "application/json"
        ErrorVariable = "invokeRestMethodError"
        WebSession = $script:sysAidWebSession 
        Body = $Payload
    }

    try{
        $response = $null
        $response = Invoke-RestMethod @invokeRestMethodSetServiceRecordsParameters
    } catch [InvalidOperationException]{
        if ($invokeRestMethodError){
            throw (Get-SysAidErrorMessage -ErrorObject $invokeRestMethodError[0])
        }
    }
    # There should be nothing viable returned here
    # return $response
}

function Add-SysAidServiceRecordNote{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [int]$ID,

        [Parameter(Mandatory=$False)]
        [string]$SubmitUserName,

        [Parameter(Mandatory=$False)]
        [datetime]$CreateDate = (Get-Date),

        [Parameter(Mandatory=$False)]
        [string]$Text = ""


    )
    # Create the note object, convert to payload, update service request. 
    $sysaidnoteObject =  (New-SysAidServiceRequestNote -SubmitUserName $SubmitUserName -CreateDate $CreateDate -Text $Text)
    Update-SysAidServiceRecord -ID $ID -Payload (New-SysAidServiceRecordPayload -Notes $sysaidnoteObject -ID $ID)
}

function Add-SysAidServiceRecordLink{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [int]$ID,

        [Parameter(Mandatory=$True)]
        [Alias("Name")]
        [string]$LinkName,

        [Parameter(Mandatory=$True)]
        [Alias("URL")]
        [uri]$Link
    )

    if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break} 

    $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + ($SysAidAPIPaths.AddServiceRequestLink -f $ID))

    # Prepare the splatting variable
    $invokeWebRequestNewServiceRecordsParameters = @{
        URI = $completeURI.Uri.AbsoluteUri
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Post
        ContentType = "application/json"
        ErrorVariable = "invokeWebRequestError"
        WebSession = $script:sysAidWebSession 
        Body = '{{"name":"{0}","link":"{1}"}}' -f $LinkName, $link.Uri.AbsoluteUri
    }

    try{
        
        Invoke-WebRequest @invokeWebRequestNewServiceRecordsParameters | Out-Null
    } catch [InvalidOperationException]{
        if ($invokeWebRequestError){
            throw (Get-SysAidErrorMessage -ErrorObject $invokeWebRequestError[0])
        }
    }

}

function Search-SysAidUser{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$Query
    )

    if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}

    $queryParameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty) 
    $queryParameters.Add("query",$Query)

    $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + $SysAidAPIPaths.SearchUsers)
    $completeURI.Query = $queryParameters.ToString()

    # Prepare the splatting variable
    $invokeWebRequestNewServiceRecordsParameters = @{
        URI = $completeURI.Uri.AbsoluteUri
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
        ContentType = "application/json"
        ErrorVariable = "invokeWebRequestError"
        WebSession = $script:sysAidWebSession 
    }

    try{
        $response = $null
        $response = Invoke-WebRequest @invokeWebRequestNewServiceRecordsParameters
    } catch [InvalidOperationException]{
        if ($invokeWebRequestError){
            throw (Get-SysAidErrorMessage -ErrorObject $invokeWebRequestError[0])
        }
    }

    return $response.Content | ConvertFrom-Json
}

function Get-SysAidList{
    [CmdletBinding(DefaultParameterSetName="All")]
    param (
        [Parameter(Mandatory=$false)]
        [ValidateSet("sr", "asset", "user", "ci", "company", "action_item", "project", "task", "catalog", "software", "sr_activity", "supplier", "task_activity", "user_groups")]
        [string]$Entity="sr",

        [Parameter(Mandatory=$false)]
        [string[]]$Fields,

        [Parameter(Mandatory=$false)]
        [int]$Offset,

        [Parameter(Mandatory=$false)]
        [int]$Limit,

        [Parameter(Mandatory=$True, ParameterSetName="ID")]
        [string]$ID
    )

    if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}

    $queryParameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty) 
    if($Entity){$queryParameters.Add("entity",$Entity.ToString())}
    if($Fields){$queryParameters.Add("fields",($Fields -join ","))}
    if($Offset){$queryParameters.Add("offset",$Offset)}
    if($Limit){$queryParameters.Add("limit",$Limit)}


    if($PSCmdlet.ParameterSetName -eq "All"){
        $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + $SysAidAPIPaths.GetAllLists)
    } else {
        $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + ($SysAidAPIPaths.GetList -f $ID))
    }
    $completeURI.Query = $queryParameters.ToString()
    
    # Prepare the splatting variable
    $invokeWebRequestGetSysAidListParameters = @{
        URI = $completeURI.Uri.AbsoluteUri
        Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
        ContentType = "application/json"
        ErrorVariable = "invokeWebRequestError"
        WebSession = $script:sysAidWebSession 
    }
    
    try{
        $response = Invoke-WebRequest @invokeWebRequestGetSysAidListParameters
    } catch [InvalidOperationException]{
        if ($invokeWebRequestError){
            throw (Get-SysAidErrorMessage -ErrorObject $invokeWebRequestError[0])
        }
    }

    return $response.Content | ConvertFrom-Json
}

function Add-SysAidServiceRequestAttachment{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$ID, 

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="File")]
        [System.IO.FileInfo]$File,

        [Parameter(Mandatory=$true, ParameterSetName="Bytes")]
        [byte[]]$Bytes,

        [Parameter(Mandatory=$true, ParameterSetName="Bytes")]
        [string]$FileName,

        [Parameter(Mandatory=$false)]
        [string]$ContentType
    )
    
    begin{
        if($null -eq $script:sysAidWebSession){Write-Error "No active WebSession to SysAid. Call the cmdlet Set-SysAidAPIWebSession first.";break}
        
        # Set an automated Content Type if one is not specified. If it cannot be determined assume application/octet-stream
        if($PSCmdlet.ParameterSetName -eq "File"){
            if (-not (Test-Path $File))    {
                $errorMessage = ("File '{0}' missing or unable to read." -f $File.FullName)
                $exception =  [System.Exception]::new($errorMessage)
                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'MultipartFormDataUpload', ([System.Management.Automation.ErrorCategory]::InvalidArgument), $File.FullName)
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
            
            if(-not $ContentType){
                Add-Type -AssemblyName System.Web
                $mimeType = [System.Web.MimeMapping]::GetMimeMapping($File.FullName)
                $ContentType = if($mimeType){$mimeType}else{$ContentType = "application/octet-stream"}
            }
        } else {
            if(-not $ContentType){$ContentType = "application/octet-stream"}
        }
    }
    process{
        Add-Type -AssemblyName System.Net.Http

        $httpClientHandler = [System.Net.Http.HttpClientHandler]::new()
        # Add the cookie from the existing web session
        $httpClientHandler.CookieContainer.Add($script:sysAidWebSession.Cookies.GetCookies($tenantURL))
        $httpClient = [System.Net.Http.Httpclient]::new($httpClientHandler)

        $contentDispositionHeaderValue = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
        # This must be file as per: https://community.sysaid.com/Sysforums/templates/default/help/files/Guide_REST_API_Details.htm#AddSRAttachment 
        $contentDispositionHeaderValue.Name = "file"

        if($PSCmdlet.ParameterSetName -eq "File"){
            try{
                $packageFileStream = [System.IO.FileStream]::new($File, [System.IO.FileMode]::Open)
            } catch {
                $errorMessage = ($_.Exception.Message)
                $exception =  [System.Exception]::new($errorMessage)
                $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'MultipartFormDataUpload', ([System.Management.Automation.ErrorCategory]::InvalidArgument), $File.FullName)
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }

            $contentDispositionHeaderValue.FileName = [system.io.path]::GetFileName($File.FullName)
            $streamContent = [System.Net.Http.StreamContent]::new($packageFileStream)
        } else {
            $contentDispositionHeaderValue.FileName = $FileName
            $streamContent = [System.Net.Http.StreamContent]::new([System.IO.MemoryStream]::new($Bytes))
        }
        
        $streamContent.Headers.ContentDisposition = $contentDispositionHeaderValue
        $streamContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new($ContentType)
        
        $content = [System.Net.Http.MultipartFormDataContent]::new()
        $content.Add($streamContent)

        try{
            $completeURI = [System.UriBuilder]($script:SysAidTenantUrl+ $SysAidAPIPaths.root + ($SysAidAPIPaths.AddServiceRequestAttachment -f $ID))
            $response = $httpClient.PostAsync($completeURI.Uri, $content).Result

            if (!$response.IsSuccessStatusCode){
                $responseBody = $response.Content.ReadAsStringAsync().Result
                $errorMessage = "Status code {0}. Reason {1}. Server reported the following message: {2}." -f $response.StatusCode, $response.ReasonPhrase, $responseBody

                throw [System.Net.Http.HttpRequestException] $errorMessage
            }
            
            if($response.Content.ReadAsStringAsync().Result){
                return $response.Content.ReadAsStringAsync().Result
            }
        }
        catch [Exception]{
            $PSCmdlet.ThrowTerminatingError($_)
        }
        finally{
            if($httpClient){$httpClient.Dispose()}
            if($response){$response.Dispose()}
        }
    }
    end {if($packageFileStream){$packageFileStream.Dispose()}}
}

