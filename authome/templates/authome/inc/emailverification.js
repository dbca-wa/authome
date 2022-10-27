var send_btn = null;
var resend_btn = null;
var change_btn = null;
var continue_btn = null;
var verify_btn = null;
var email_field = null;

var verifycode_field = null;
var action = null;
var email = null;

function sendcode_succeed() {
    email_field.prop('readonly', true)
    email_field.prop('disabled', true)
    verifycode_field.show()

    send_btn.prop('disabled', true)
    send_btn.hide()

    verify_btn.prop('disabled', false)
    verify_btn.show()

    resend_btn.prop('disabled', false)
    resend_btn.show()

    if (email_readonly) {
        change_btn.prop('readonly', true)
        change_btn.prop('disabled', true)
    } else {
        change_btn.prop('readonly', false)
        change_btn.prop('disabled', false)
        change_btn.show()
    }

    continue_btn.hide()
}
function sendcode_failed() {
    verifycode_field.hide()

    send_btn.prop('disabled', false)
    send_btn.show()

    verify_btn.prop('disabled', true)
    verify_btn.hide()

    resend_btn.prop('disabled', true)
    resend_btn.hide()

    if (email_readonly) {
        email_field.prop('readonly', true)
        email_field.prop('disabled', true)
    } else {
        change_btn.prop('disabled', true)
        change_btn.hide()
        email_field.prop('readonly', false)
        email_field.prop('disabled', false)
    }

    continue_btn.hide()
}
function resendcode_succeed() {
    email_field.prop('readonly', true)
    email_field.prop('disabled', true)
    verifycode_field.show()

    send_btn.prop('disabled', true)
    send_btn.hide()

    verify_btn.prop('disabled', false)
    verify_btn.show()

    resend_btn.prop('disabled', false)
    resend_btn.show()

    if (!email_readonly) {
        change_btn.prop('disabled', false)
        change_btn.show()
    }

    continue_btn.hide()
}
function resendcode_failed() {
    email_field.prop('readonly', true)
    email_field.prop('disabled', true)
    verifycode_field.show()

    send_btn.prop('disabled', true)
    send_btn.hide()

    verify_btn.prop('disabled', false)
    verify_btn.show()

    resend_btn.prop('disabled', false)
    resend_btn.show()

    if (!email_readonly) {
        change_btn.prop('disabled', false)
        change_btn.show()
    }

    continue_btn.hide()
}
function change_succeed() {
    verifycode_field.hide()

    send_btn.prop('disabled', false)
    send_btn.show()

    verify_btn.prop('disabled', true)
    verify_btn.hide()

    resend_btn.prop('disabled', true)
    resend_btn.hide()

    if (!email_readonly) {
        change_btn.prop('disabled', true)
        change_btn.hide()
        email_field.prop('readonly', false)
        email_field.prop('disabled', false)
        if (!email_field.val()) {
            email_field.val(email)
        }
    }

    continue_btn.hide()
}
function verifycode_succeed() {
    email_field.prop('readonly', true)
    email_field.prop('disabled', true)
    verifycode_field.hide()

    send_btn.prop('disabled', true)
    send_btn.hide()

    verify_btn.prop('disabled', true)
    verify_btn.hide()

    resend_btn.prop('disabled', true)
    resend_btn.hide()

    change_btn.prop('disabled', true)
    change_btn.hide()

    continue_btn.hide()
    continue_btn.click()
}
function verifycode_failed() {
    email_field.prop('readonly', true)
    email_field.prop('disabled', true)
    verifycode_field.show()

    send_btn.prop('disabled', true)
    send_btn.hide()

    verify_btn.prop('disabled', false)
    verify_btn.show()

    resend_btn.prop('disabled', false)
    resend_btn.show()

    if (!email_readonly) {
        change_btn.prop('disabled', false)
        change_btn.show()
    }

    continue_btn.hide()
}
function disable_btns() {
    email_field.prop('readonly', true)
    email_field.prop('disabled', true)
    send_btn.prop('disabled', true)
    verify_btn.prop('disabled', true)
    resend_btn.prop('disabled', true)
    if (!email_readonly) {
        change_btn.prop('disabled', true)
    }
    continue_btn.hide()
}

function get_element(id) {
    return ($("#" + id).length)?$("#" + id):null;
}


$(document).ready(function () { 
    continue_btn = get_element("continue")
    send_btn = get_element(btn_prefix + "_but_send_code")
    resend_btn = get_element(btn_prefix + "_but_send_new_code")
    change_btn = get_element(btn_prefix + "_but_change_claims")
    verify_btn = get_element(btn_prefix + "_but_verify_code")
    email_field = get_element(emailid)
    verifycode_field = get_element("VerificationCode")
    if (!continue_btn || !send_btn || !resend_btn || !change_btn || !verify_btn || !email_field || !verifycode_field){
        //logic changed , need to adjust the logic again.
        return
    }
    continue_btn.hide()
    verify_btn.hide()
    resend_btn.hide()
    change_btn.hide()
    change_btn.prop('disabled', true)

    if (email_readonly) {
        email_field.prop('readonly', true)
        email_field.prop('disabled', true)

        send_btn.hide()
    } else {
        email_field.prop('readonly', false)
        email_field.prop('disabled', false)

        email_field.keypress(function(event) {
            // If the user presses the "Enter" key on the keyboard
            var keycode = (event.keyCode ? event.keyCode : event.which);
            if(keycode == '13') { 
                send_btn.focus()
            }
        }); 

        send_btn.show()
    }

    verifycode_field.keypress(function(event) {
        // If the user presses the "Enter" key on the keyboard
        var keycode = (event.keyCode ? event.keyCode : event.which);
        if(keycode == '13') { 
            if (verifycode_field.val().trim()) {
                action = "verify_code"
                disable_btns()
            } else {
                verifycode_failed()
            }
            continue_btn.hide()
        }
    }); 
    //attach a click event in the end to control the page 
    send_btn.click(function(){
        if (email_field.val().trim()) {
            action = "send_code"
            disable_btns()
            email = email_field.val()
        } else {
            sendcode_failed()
        }
    })

    verify_btn.click(function(){
        if (verifycode_field.val().trim()) {
            action = "verify_code"
            disable_btns()
        } else {
            verifycode_failed()
        }
        continue_btn.hide()
    })

    change_btn.click(function(){
        action = "change_email"
        change_succeed()
    })

    resend_btn.click(function(){
        action = "resend_code"
        disable_btns()
    })

    if (email_readonly) {
        send_btn.click()
    }
})
$.ajaxSetup({
    beforeSend:function(xhr,settings) {
        email_field.prop("disabled",false)
        xhr.url = settings.url

    }
})
$(document).ajaxComplete(function(event,xhr,options) {
    if (!action) {
        return
    }
    url = xhr.url.toLowerCase()
    //sendcode 
    status = parseInt(xhr.status)
    if (status < 200 || status >= 300) {
        if (action == "send_code") {
            sendcode_failed()
        } else if ( action == "verify_code") {
            verifycode_failed()
        } else if (action == "resend_code"){
            resendcode_failed()
        }
    } else {
        var res = xhr.responseJSON
        if (!res) {
            return
        }
        status = parseInt(res.status)
        if (status >=200 && status < 300) {
            if (action == "send_code") {
                sendcode_succeed()
            } else if ( action == "verify_code") {
                verifycode_succeed()
            } else if (action == "resend_code"){
                resendcode_succeed()
            }
        } else {
            if (action == "send_code") {
                sendcode_failed()
            } else if ( action == "verify_code") {
                verifycode_failed()
            } else if (action == "resend_code"){
                resendcode_failed()
            }
        }
    }
    action = null
});
