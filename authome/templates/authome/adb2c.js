var createAccount = document.getElementById("createAccount")
var forgotPassword = document.getElementById("forgotPassword")
if (createAccount && forgotPassword){
    createAccount.href = "{{email_signup_url}}"
    forgotPassword.href = "{{password_reset_url}}"
} else {    
    // Select the node that will be observed for mutations
    const targetNode = document.getElementById('api');
    
    // Options for the observer (which mutations to observe)
    const config = {  childList: true, subtree: true,attributes:true };
    
    // Callback function to execute when mutations are observed
    const callback = function(mutationsList, observer) {
        createAccount = document.getElementById("createAccount")
        forgotPassword = document.getElementById("forgotPassword")
        if (createAccount && forgotPassword){
            observer.disconnect();
            createAccount.href = "{{email_signup_url}}"
            forgotPassword.href = "{{password_reset_url}}"
        }
    }
    // Create an observer instance linked to the callback function
    const observer = new MutationObserver(callback);
    // Start observing the target node for configured mutations
    observer.observe(targetNode, config);
}


