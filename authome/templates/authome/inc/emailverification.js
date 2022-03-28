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
    email_field.attr('readonly', true)
    verifycode_field.show()

    send_btn.attr('disabled', true)
    send_btn.hide()

    verify_btn.attr('disabled', false)
    verify_btn.show()

    resend_btn.attr('disabled', false)
    resend_btn.show()

    if (!email_readonly) {
        change_btn.attr('disabled', false)
        change_btn.show()
    }

    continue_btn.hide()
}
function sendcode_failed() {
    verifycode_field.hide()

    send_btn.attr('disabled', false)
    send_btn.show()

    verify_btn.attr('disabled', true)
    verify_btn.hide()

    resend_btn.attr('disabled', true)
    resend_btn.hide()

    if (!email_readonly) {
        change_btn.attr('disabled', true)
        change_btn.hide()
        email_field.attr('readonly', false)
    }

    continue_btn.hide()
}
function resendcode_succeed() {
    email_field.attr('readonly', true)
    verifycode_field.show()

    send_btn.attr('disabled', true)
    send_btn.hide()

    verify_btn.attr('disabled', false)
    verify_btn.show()

    resend_btn.attr('disabled', false)
    resend_btn.show()

    if (!email_readonly) {
        change_btn.attr('disabled', false)
        change_btn.show()
    }

    continue_btn.hide()
}
function resendcode_failed() {
    email_field.attr('readonly', true)
    verifycode_field.show()

    send_btn.attr('disabled', true)
    send_btn.hide()

    verify_btn.attr('disabled', false)
    verify_btn.show()

    resend_btn.attr('disabled', false)
    resend_btn.show()

    if (!email_readonly) {
        change_btn.attr('disabled', false)
        change_btn.show()
    }

    continue_btn.hide()
}
function change_succeed() {
    verifycode_field.hide()

    send_btn.attr('disabled', false)
    send_btn.show()

    verify_btn.attr('disabled', true)
    verify_btn.hide()

    resend_btn.attr('disabled', true)
    resend_btn.hide()

    if (!email_readonly) {
        change_btn.attr('disabled', true)
        change_btn.hide()
        email_field.attr('readonly', false)
        if (!email_field.val()) {
            email_field.val(email)
        }
    }

    continue_btn.hide()
}
function verifycode_succeed() {
    email_field.attr('readonly', true)
    verifycode_field.hide()

    send_btn.attr('disabled', true)
    send_btn.hide()

    verify_btn.attr('disabled', true)
    verify_btn.hide()

    resend_btn.attr('disabled', true)
    resend_btn.hide()

    change_btn.attr('disabled', true)
    change_btn.hide()

    continue_btn.hide()
    continue_btn.click()
}
function verifycode_failed() {
    email_field.attr('readonly', true)
    verifycode_field.show()

    send_btn.attr('disabled', true)
    send_btn.hide()

    verify_btn.attr('disabled', false)
    verify_btn.show()

    resend_btn.attr('disabled', false)
    resend_btn.show()

    if (!email_readonly) {
        change_btn.attr('disabled', false)
        change_btn.show()
    }

    continue_btn.hide()
}
function disable_btns() {
    email_field.attr('readonly', true)
    send_btn.attr('disabled', true)
    verify_btn.attr('disabled', true)
    resend_btn.attr('disabled', true)
    if (!email_readonly) {
        change_btn.attr('disabled', true)
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
    send_btn.show()
    verify_btn.hide()
    resend_btn.hide()
    change_btn.hide()
    change_btn.attr('disabled', true)
    if (email_readonly) {
        email_field.attr('readonly', true)
    } else {
        email_field.attr('readonly', false)
    }
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

})
$.ajaxSetup({
    beforeSend:function(xhr,settings) {
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
