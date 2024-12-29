function doGet(req) {
    var empid = req.parameter.empid;
    var emppass = req.parameter.emppass;
    var emphash = req.parameter.emphash;
    var authtoken = req.parameter.authtoken;
    var subdomains = req.parameter.subdomains;
    var subdomain = req.parameter.subdomain;
    var newPass = req.parameter.newPass;
    var build_number = req.parameter.build_number;
    var is_from_script = req.parameter.is_from_script === 'true';
    var update_entry = req.parameter.update_entry === 'true';
    var create_entry = req.parameter.create_entry === 'true';
    var fetch_entry = req.parameter.fetch_entry === 'true';
    var build_number_generate = req.parameter.build_number_generate === 'true';
    var forgetpass = req.parameter.forgetpass === 'true';
    var emplogin = req.parameter.emplogin === 'true';
    var datahash = req.parameter.datahash;

    // var authtoken = "QlMxNjE0OjE3MzU0MDUxMjYyNDY6NDkzMzdrMDY3NDgx";
    // var empid = "BS1614";
    // var is_from_script = false;
    // var emppass = "";
    // var emphash = "";
    // var subdomains = "";
    // var subdomain = "";
    // var build_number = "";
    // var update_entry = false;
    // var create_entry = false;
    // var fetch_entry = false;
    // var forgetpass = true;
    // var datahash = "";
    // var newPass = "11"


    var appListsSheet = fetchAppSheet();
    if (appListsSheet == -1) {
      return createJsonResponse("Sheet 'APPLISTS' not found.",true);
    }

    // var logSheet = logSheet();
    // if (logSheet == -1) {
    //     return createJsonResponse("Sheet 'LogSheet' not found.",true);
    // }

    var credentialSheet = credentialsSheet();
    if (credentialSheet == -1) {
      return createJsonResponse("Sheet 'credentials' not found.",true);
    }

    if(is_from_script){
        if(build_number!="" && subdomain!="" && update_entry){
            // Change Auto generated Build Number to 200 consider build generated
            return buildNumberRevert(appListsSheet,build_number,subdomain);

        }else if(build_number!="" && fetch_entry){
            // Fetch App list with respect of build number
            return fetchScriptAppLists(appListsSheet,build_number);

        }else{
            // Error File error
            return createJsonResponse("No matching requests!",true);
        }
    }
    if(forgetpass){
        //
        if (typeof empid === 'string' && empid.trim() !== "" && typeof newPass === 'string' && newPass.trim() !== "" && typeof authtoken === 'string' && authtoken.trim() !== "") {
            //console.log("daaa");
            //return createJsonResponse("No matching forget !",true);
            return forgetPasswordTwo(credentialSheet,empid, authtoken, newPass);
        }
        if(empid!=""){
            //return createJsonResponse("No matching forget 23!",true);
            //forget password
            // Step - 1: check empid valid or not
            // Step - 2: If valid check email id present or not? If email present sent email.
            // Step - 3: proceed next page with authtoken(valid for 30min) 
            // Step - 4: enter OTP(from email), newpass , confirmpass and token
            // Step - 5: Valid everything correct change password.
            return forgetPasswordOne(credentialSheet,empid);
        }
    }
    if(emplogin){
        //return createJsonResponse("No matching emplogin !",true);

        if(empid!="" && emppass!="") {
            return employeelogin(credentialSheet,empid,emppass);
        }
    }
    
    if(authtoken!="" && empid!=""){
        var response = isValidToken(credentialSheet,authtoken, empid);
        console.log("00"+JSON.stringify(response));
        if (response.code === 200) {
            if(authtoken!="" && fetch_entry){
                // Consider this is first fetch data to show in front UI
                console.log("11");
                return fetchAppLists(appListsSheet);
                
            }else if(authtoken!="" && subdomains!=""){
                // Consider this is required to generate Build Number
                console.log("22");
                return buildNumberGeneration(appListsSheet,subdomains);

            }else if(authtoken!="" && create_entry && datahash!=""){
                // Consider this is new entry should append on the last row of excel
                console.log("33");
                return newOperatorEntry(datahash);

            }else if(authtoken!="" && update_entry && datahash!="" && subdomain!=""){
                // Consider update the entry with valid subdomain and also whatever data send only those data will update 
                console.log("44");
                return updateOperatorEntry(subdomain,datahash);

            }else{
                console.log("55");
                // Throw error as there are no matching requests.
                return createJsonResponse("No matching requests!",true);
            }
        }else{
            console.log("66 Error => "+JSON.stringify(response));
            return ContentService.createTextOutput(JSON.stringify(response)).setMimeType(ContentService.MimeType.JSON);
        }
    }
       
    // Throw error as there are no matching requests.
    return createJsonResponse("No matching requests!",true);
    
}

function fetchAppSheet(){
    var sheetId = "1_rqv6H1fKyt2TbvfHP9UyDkr0DRSvpTSJdOAFruIsw4";
    var doc = SpreadsheetApp.openById(sheetId);
    var sheet = doc.getSheetByName('APPLISTS');

    if (!sheet) {
      return -1;
    }

    return sheet;
}

function logSheet(){
    var sheetId = "1_rqv6H1fKyt2TbvfHP9UyDkr0DRSvpTSJdOAFruIsw4";
    var doc = SpreadsheetApp.openById(sheetId);
    var logSheet = doc.getSheetByName('LOGSHEET') || doc.insertSheet('LOGSHEET');

    if (!logSheet) {
      return -1;
    }

    return logSheet;
}

function credentialsSheet(){
    var sheetId = "1CwOPtJ-uCFyz683gruhlsAOm6WxbUXlymub4xLveeZI";
    var credentialsdoc = SpreadsheetApp.openById(sheetId);
    var credentialSheet = credentialsdoc.getSheetByName('credentials');
    return credentialSheet;
}

function createJsonResponse(message,is_json_Return=false,code=400) {
    var response = {
      code: code,
      message: message
    };
    
    if(is_json_Return){
      return ContentService.createTextOutput(JSON.stringify(response)).setMimeType(ContentService.MimeType.JSON);
    }else{
      return response;
    } 
}

function findRowBySubdomain(subdomain, data) {
    const subdomainColumnIndex = 3;
    for (let i = 1; i < data.length; i++) {
      if (data[i][subdomainColumnIndex].toString().trim() === subdomain) {
        return i + 1;
      }
    }
    return -1;
}

function findRowIndex(empId, empPass, svalues,onlyempId=false) {
    for (let i = 1; i < svalues.length; i++) {
        if(onlyempId){
            if (svalues[i][0].toString().trim() === empId) {
                return i + 1;
            }
        }else{
            if (svalues[i][0].toString().trim() === empId && svalues[i][2].toString().trim() === empPass) {
                return i + 1;
            }
        }
       
    }
    return -1;
}

function generateAccessToken(secret,setdays=true,dvalue=2,setmin=false,fgetotp="") {
    //var timestamp = new Date().getTime().toString();
    var timestamp = getFormattedDate(setdays,dvalue,setmin)
    var randomValue = Math.floor(Math.random() * 1000000).toString();
    if(fgetotp!=""){
        var token = secret + ":" + timestamp + ":" + randomValue+"k"+fgetotp;
    }else{
        var token = secret + ":" + timestamp + ":" + randomValue;
    }
    var accessToken = Utilities.base64EncodeWebSafe(token).replace(/=+$/, '');
    //Logger.log("Generated Access Token: " + accessToken);
    return accessToken;
}

function SixDigitOTP(){
    return Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
}

function decodeAccessToken(encodedToken) {
    // Convert URL-safe Base64 to standard Base64
    var base64String = encodedToken
        .replace(/-/g, '+')   // Replace `-` with `+`
        .replace(/_/g, '/');   // Replace `_` with `/`

    // Decode the Base64 string using Google Apps Script's Utilities.base64Decode
    var decodedBytes = Utilities.base64Decode(base64String);
    
    // Convert the bytes to a string (assuming UTF-8 encoding)
    var decodedString = Utilities.newBlob(decodedBytes).getDataAsString();
    
    return decodedString;
}

function encryptPassword(password) {
    return Utilities.base64Encode(Utilities.newBlob(password).getBytes());
}

function isValidToken(credentialSheet,token, secretkey) {

    var credentialSheetValues = credentialSheet.getDataRange().getValues();
    var filteredRows = credentialSheetValues.slice(1).filter(row => row[3].toString().trim() === token);

    if (filteredRows.length === 0) {
        return createJsonResponse("Access Token Invalid!-1");
    }

    try {
        var savedTimestamp = filteredRows[0][4].toString().trim();
        var decodedToken = decodeAccessToken(token);

        var [decodedSecret, timestamp, randomValue] = decodedToken.split(":");

        if (decodedSecret === secretkey) {
            var currentTimestamp = new Date().getTime();
            var differenceInSeconds = Math.floor((savedTimestamp - currentTimestamp) / 1000);

            if (differenceInSeconds <= 0) {
                return createJsonResponse("Access Token Expired!");
            }

            return {
                code: 200,
                message: "Access Token Valid!",
                differenceInSeconds: differenceInSeconds,
                employee_data: filteredRows.map(row => ({
                    emp_id: row[0],
                    emp_email: row[1]
                }))
            };
        } else {
            return createJsonResponse("Access Token Invalid!-2");
        }
    } catch (error) {
        return createJsonResponse("Access Token Invalid!-3 " + error.message);
    }
}

function decryptPassword(base64String) {
    // Convert the URL-safe Base64 back to standard Base64
    let standardBase64 = base64String.replace(/-/g, '+').replace(/_/g, '/');
    
    // Add padding ('=' characters) if necessary
    let padding = standardBase64.length % 4;
    if (padding > 0) {
      standardBase64 += '='.repeat(4 - padding);  // Add '=' to make length a multiple of 4
    }
    
    // Decode the Base64 string
    let decodedBytes = Utilities.base64Decode(standardBase64);
    
    // Convert bytes back to string
    let decodedString = Utilities.newBlob(decodedBytes).getDataAsString();
    
    return decodedString;
}

function getFormattedDate(setdays=true,dvalue=2,setmin=false) {
    var currentDate = new Date();  // Current date and time
    if(setdays){
        currentDate.setDate(currentDate.getDate() + dvalue);  // Add 2 days
    }
    if(setmin){
        currentDate.setMinutes(currentDate.getMinutes() + dvalue);
    }
    var timestamp = currentDate.getTime();  // Convert to timestamp
    // Logger.log("Updated Timestamp: " + timestamp);
    return timestamp;
}

function sendOtpEmail(recipient,otp) {
    var subject = "Your One-Time Password (OTP) for Account Verification";  // Email subject
    
    // Email body with OTP
    var body = `
      <p>Dear User,</p>
      <p>We received a request to verify your account. Please use the following One-Time Password (OTP) to complete the process:</p>
      <p><strong>OTP: ${otp}</strong></p>
      <p>This OTP is valid for 10 minutes only and can only be used once.</p>
      <p>If you did not request this OTP, please ignore this email or contact support immediately.</p>
      <p>Thank you,<br>The Support Team</p>
    `;  // HTML email body
  
    // Send the OTP email
    MailApp.sendEmail({
      to: recipient,
      subject: subject,
      body: body,  // Plain text version of the body
      htmlBody: body  // HTML version of the body
    });
  
    Logger.log("OTP email sent successfully to " + recipient);
}
  
// Function to generate a random 6-digit OTP
function generateOtp() {
    var otp = Math.floor(100000 + Math.random() * 900000);  // Generates a 6-digit number
    return otp.toString();  // Returns OTP as a string
}
  

//  API Functions
function buildNumberRevert(appListsSheet, build_number,subdomain){

    var values = appListsSheet.getDataRange().getValues();

    var matchingRows = values.slice(1).filter(function(row) {
        return row[0] == build_number && subdomain == row[3].toString().trim();
    });

    if (matchingRows.length === 0) {
        return createJsonResponse("No matching Build Number found.",true);
    }
    matchingRows.forEach(function(row) {
        var rowIndex = values.indexOf(row);
        appListsSheet.getRange(rowIndex + 1, 1).setValue(200); 
    });
    return createJsonResponse("Build Number updated successfully",true,200);
}

function fetchScriptAppLists(appListsSheet,build_number){
    var values = appListsSheet.getDataRange().getValues();
    var filteredRows = values.slice(1).filter(row => row[0].toString().trim() === build_number.toString().trim());    
    if (filteredRows.length > 0) {
        filteredRows.forEach((row) => {
            var version = parseFloat(row[1]);
            var versionCode = parseInt(row[2]);
            var subDomain = row[3].toString().trim();
            var originalRowIndex = findRowBySubdomain(subDomain, values);

            appListsSheet.getRange(originalRowIndex, 2).setValue((version + 0.1).toFixed(1));
            appListsSheet.getRange(originalRowIndex, 3).setValue(versionCode + 1);
        });
    }
    var output = filteredRows.map(row => [
        row[0],   // build_required
        row[1],   // version
        row[2],   // version_code
        row[3].toString().trim(),   // sub_domain
        row[4].toString(),           // key_file_name
        row[5].toString(),           // alias_name
        row[6].toString().trim(),    // password
        row[7].toString(),           // android_package_name
        row[8].toString(),           // operator_name
        row[9].toString().trim(),    // base_url
        row[10].toString().trim()    // country_name
    ].join(",")).join("\n");

    return ContentService.createTextOutput(output+ "\n").setMimeType(ContentService.MimeType.TEXT);
}

function employeelogin(credentialSheet,empId,empPass){
    var svalues = credentialSheet.getDataRange().getValues();
    var empToken = generateAccessToken(empId);
    var encrytppass = encryptPassword(empPass.toString().trim());
    originalRowIndex = findRowIndex(empId, encrytppass, svalues);
    
    filteredRows = svalues.slice(1).filter(row => row[0].toString().trim()==empId.toString().trim() && row[2].toString().trim()==encrytppass );
    if (filteredRows.length > 0){
        var responseObject = {
            code: 200,
            message: "Logged In Successfully",
            data: {
                empid: empId.toString().trim(),
                empToken: empToken
            }
        };
        credentialSheet.getRange(originalRowIndex, 4).setValue(empToken);
        credentialSheet.getRange(originalRowIndex, 5).setValue(getFormattedDate());
        // console.log(responseObject);
        return ContentService.createTextOutput(JSON.stringify(responseObject)).setMimeType(ContentService.MimeType.JSON);
    }else{
      return createJsonResponse("Wrong Credentials!",true);
    }
}

function forgetPasswordOne(credentialSheet,empId){
    var svalues = credentialSheet.getDataRange().getValues();
    fgetotp = SixDigitOTP();
    var forgetpasstoken = generateAccessToken(empId,false,30,true,fgetotp);
    originalRowIndex = findRowIndex(empId, "", svalues,true);
    
    filteredRows = svalues.slice(1).filter(row => row[0].toString().trim()==empId.toString().trim() && row[1].toString().trim()!= "" );
    if (filteredRows.length > 0){
        // fetch emp email from row[1]
        var empEmail = filteredRows[0][1];
        // console.log(empEmail);
        // console.log(forgetpasstoken);
        // console.log(fgetotp);
        sendOtpEmail(empEmail,fgetotp);

        var responseObject = {
            code: 200,
            message: "OTP sent Successfully",
            data: {
                fgetToken: forgetpasstoken
            }
        };
        credentialSheet.getRange(originalRowIndex, 6).setValue(forgetpasstoken);
        // console.log(responseObject);
        return ContentService.createTextOutput(JSON.stringify(responseObject)).setMimeType(ContentService.MimeType.JSON);
    }else{
        return createJsonResponse("Wrong Credentials!",true);
    }
}

function forgetPasswordTwo(credentialSheet,empId,token, newPass){
    var svalues = credentialSheet.getDataRange().getValues();
    originalRowIndex = findRowIndex(empId, "", svalues,true);
    //console.log("sadwww",token);
    filteredRows = svalues.slice(1).filter(row => row[0].toString().trim()==empId.toString().trim() && row[5].toString().trim()==token );
    if (filteredRows.length > 0){
       // console.log("sadwww");
        var encrypt_pass = encryptPassword(newPass);

        var responseObject = {
            code: 200,
            message: "Password Updated Successfully"
        };
        credentialSheet.getRange(originalRowIndex, 3).setValue(encrypt_pass);
        credentialSheet.getRange(originalRowIndex, 6).setValue("");
        // console.log(responseObject);
        return ContentService.createTextOutput(JSON.stringify(responseObject)).setMimeType(ContentService.MimeType.JSON);
    }else{
      //console.log("sad");
      return createJsonResponse("Wrong Credentials!",true);
    }
}

function fetchAppLists(appListsSheet){
    var values = appListsSheet.getDataRange().getValues();
    var filteredRows = values.slice(1).filter(row => row[7]);
    
    var responseObject = {
        code: 200,
        message: "Active App Lists",
        app_lists: filteredRows.map(function(row) {
            return {
            build_required: row[0],
            version: row[1],
            version_code: row[2],
            sub_domain: row[3].toString().trim(),
            key_file_name: row[4].toString(),
            alias_name: row[5].toString(),
            password: row[6].toString().trim(),
            android_package_name: row[7].toString(),
            operator_name: row[8].toString(),
            base_url: row[9].toString().trim(),
            country_name: row[10].toString().trim(),
            developer_name: row[11] ? row[11].toString().trim() : "-",
            last_app_published_date: row[12] ? row[12].toString().trim() : "-",
            playstore_link: row[13] ? row[13].toString().trim() : "-",
            region: row[14] ? row[14].toString().trim() : "-",
            analytics_email: row[15] ? row[15].toString().trim() : "-",
            analytics_property: row[16] ? row[16].toString().trim() : "-"
            };
        })
    };
    console.log(responseObject);
    return ContentService.createTextOutput(JSON.stringify(responseObject)).setMimeType(ContentService.MimeType.JSON);
}

function buildNumberGeneration(appListsSheet,subdomains){
    var values = appListsSheet.getDataRange().getValues();
    var subdomainsList = subdomains.split(',').map(function(subdomain) {
        return subdomain.trim();
    })
    var matchingRows = values.slice(1).filter(function(row) {
        return subdomainsList.includes(row[3].toString().trim()); // Check if sub_domain matches
    });
    if (matchingRows.length === 0) {
        console.log("No matching subdomain's found!");
        return createJsonResponse("No matching subdomain's found!",true);
    }
    // var newBuildRequired = generateRandomNumber(); 
    var newBuildRequired = Math.floor(100000 + Math.random() * 900000);
    matchingRows.forEach(function(row) {
        var rowIndex = values.indexOf(row);  // Get the row index (1-based)
        // Update the build_required column (column 1)
        appListsSheet.getRange(rowIndex + 1, 1).setValue(newBuildRequired);
    });
    var responseObject = {
        build_required: newBuildRequired,
        app_lists: matchingRows.map(function(row) {
            return {
                build_required: newBuildRequired,
                version: (parseFloat(row[1]) + 0.1).toFixed(1),
                version_code: parseInt(row[2]) + 1,
                sub_domain: row[3].toString().trim(),
                key_file_name: row[4].toString(),
                alias_name: row[5].toString(),
                password: row[6].toString().trim(),
                android_package_name: row[7].toString(),
                operator_name: row[8].toString(),
                base_url: row[9].toString().trim(),
                country_name: row[10].toString().trim(),
                developer_name: row[11] ? row[11].toString().trim() : "-",
                last_app_published_date: row[12] ? row[12].toString().trim() : "-",
                playstore_link: row[13] ? row[13].toString().trim() : "-",
                region: row[14] ? row[14].toString().trim() : "-",
                analytics_email: row[15] ? row[15].toString().trim() : "-",
                analytics_property: row[16] ? row[16].toString().trim() : "-"
            };
        })
    };   
    console.log(responseObject);
    return ContentService.createTextOutput(JSON.stringify(responseObject)).setMimeType(ContentService.MimeType.JSON);
}

function newOperatorEntry(datahash){

}

function updateOperatorEntry(subdomain,datahash){

}