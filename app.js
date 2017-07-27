/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request');

var isReportActivated = false;
var seqMessageOfReport = 0;

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
  console.log(event);
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

    sendTextMessage(senderID, "Quick reply tapped");
    return;
  }

  if (messageText) {
    console.log(isReportActivated);
    console.log(messageText.indexOf('report') !== -1);
    console.log(messageText.indexOf('report') !== -1 && !isReportActivated);

    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (true) {
      
      case messageText.indexOf('list') !== -1 && !isReportActivated:
        sendList(senderID);
        break;

      case messageText.indexOf('image') !== -1 && !isReportActivated:
        sendImageMessage(senderID);
        break;

      case messageText.indexOf('gif') !== -1 && !isReportActivated:
        sendGifMessage(senderID);
        break;

      case messageText.indexOf('audio') !== -1 && !isReportActivated:
        sendAudioMessage(senderID);
        break;

      case messageText.indexOf('video')!== -1 && !isReportActivated:
        sendVideoMessage(senderID);
        break;

      case messageText.indexOf('file')!== -1 && !isReportActivated:
        sendFileMessage(senderID);
        break;

      case messageText.indexOf('menu') !== -1 && !isReportActivated:
        sendButtonMessage(senderID);
        break;

      case messageText.indexOf('generic') !== -1 && !isReportActivated:
        sendGenericMessage(senderID);
        break;

      case messageText.indexOf('more picture') !== -1 && !isReportActivated: 
        sendMultipleImages(senderID);
        break;

      case messageText.indexOf('receipt') !== -1 && !isReportActivated:
        sendReceiptMessage(senderID);
        break;

      case messageText.indexOf('quick reply') !== -1 && !isReportActivated:
        sendQuickReply(senderID);
        break;        

      case messageText.indexOf('read receipt') !== -1 && !isReportActivated:
        sendReadReceipt(senderID);
        break;        

      case messageText.indexOf('typing on') !== -1 && !isReportActivated:
        sendTypingOn(senderID);
        break;        

      case messageText.indexOf('typing off') !== -1 && !isReportActivated:
        sendTypingOff(senderID);
        break;        

      case messageText.indexOf('account linking') !== -1 && !isReportActivated:
        sendAccountLinking(senderID);
        break;

      case messageText.indexOf('report') !== -1:
        isReportActivated = true;
        console.log(event.message);
        forwardMessage(senderID, event.message);
        break;

      case isReportActivated:
        console.log(event.message);
        forwardMessage(senderID, event.message);
        break;

      default:
        const numberOfMeow = Math.floor(2 * Math.random()) + 1;
        let message = '';
        for (let i = 0; i < numberOfMeow; i++) {
          message += 'Meow' + ' ';
        }

        if (messageText == "hey") {
          message = "hey"+ event.recipient.name;
        }
        
        sendTextMessage(senderID, message);
    }
    
  } else if (messageAttachments) {
    switch(true) {
      case isReportActivated:
        console.log(event.message);
        forwardMessage(senderID, event.message);
        break;
      default:
        sendTextMessage(senderID, "Message with attachment received");
    }
  }
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to 
  // let them know it was successful
  sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 * 
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: 1539856399445843
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: "https://scontent.xx.fbcdn.net/v/t34.0-12/20401294_1737668292928041_72363331_n.jpg?_nc_ad=z-m&oh=0e783bf5b528b9bf0e8adcae98925649&oe=597AC054"
          // url: "http://cdn1-www.dogtime.com/assets/uploads/gallery/30-impossibly-cute-puppies/impossibly-cute-puppy-2.jpg"
          // url: SERVER_URL + "/assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "/assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: SERVER_URL + "/assets/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a file using the Send API.
 *
 */
function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: SERVER_URL + "/assets/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "What can I do for you?",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "What's new?"
          }, 
          {
            type: "postback",
            title: "Report!",
            payload: "Report!",
          }, 
          // {
          //   type: "phone_number",
          //   title: "Call Emergency / NGO",
          //   payload: "+60179556908"
          // },
          {
            type: "web_url",
            url: "https://www.facebook.com/nowhat.hk/videos/256977024819189/?hc_ref=ARRh6DTPy4r1jtB2GSUtXVRR6vKCt-aCvUDzCR40MqdMzXJsJKOWXdqvnOh9u-lx8oY",
            title: "View Post"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",               
            image_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQBta-66htflwi-K&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12602069_1350608345000055_9152154959326740480_n.jpg%3Foh%3D94a78537864e25e5b0c0067dfe89bc4a%26oe%3D59B5B9E8&_nc_hash=AQDXEZQ5Q2GI33IR",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",               
            image_url: "https://scontent.oculuscdn.com/t64.5771-25/12139289_377088419322281_3571472392767143936_n.png/hand-controller.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",        
          timestamp: "1428444852", 
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQBta-66htflwi-K&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12602069_1350608345000055_9152154959326740480_n.jpg%3Foh%3D94a78537864e25e5b0c0067dfe89bc4a%26oe%3D59B5B9E8&_nc_hash=AQDXEZQ5Q2GI33IR",
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQBta-66htflwi-K&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12602069_1350608345000055_9152154959326740480_n.jpg%3Foh%3D94a78537864e25e5b0c0067dfe89bc4a%26oe%3D59B5B9E8&_nc_hash=AQDXEZQ5Q2GI33IR",
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Forward a message with Send API.
 *
 */
function forwardMessage(recipientId, message) {
  const moderatorId = 1779902678693258;

  var constructedMessage;
  var msgReplied = [
    "",
    "Ok. I'm listening...",
    "Pen and paper are ready.",
    "I'm here to listen.",
    "Continue.",
  ];

  if ( isReportActivated ) {
    console.log(recipientId, message);
    console.log(message !== undefined);
    console.log(message.mid !== undefined);
    console.log(message.text !== undefined);
    console.log(message.attachments !== undefined);

    if ( message.mid !== undefined && message.text !== "end report") {
      var min = Math.ceil(0);
      var max = Math.floor(msgReplied.length);
      const msgIndex = Math.floor(Math.random() * (max - min + 1)) + min;
      sendTextMessage(recipientId, msgReplied[msgIndex]);
     
      seqMessageOfReport ++;

      if ( message.text !== undefined ) {
        constructedMessage = {
          text: 'Report: ' + recipientId + '\n ============ '+ seqMessageOfReport +' ============ \n' + message.text,
        }
      } else if ( message.attachments !== undefined && message.attachments[0].type == "image" ) {
        constructedMessage = {
          text: 'Report: ' + recipientId + '\n ============ '+ seqMessageOfReport +' ============ \n' + message.attachments[0].payload.url,
        }
      }

      var reportMessageData = {
        recipient: {
          id: moderatorId
        },
        message: constructedMessage,
      }

      console.log(constructedMessage);
      console.log(reportMessageData);

      callSendAPI(reportMessageData);

    } else if (message.mid !== undefined && message.text == "end report") {
      sendTextMessage(recipientId, "All information you reported had been noted down.");
      const endMsg = "==   End of Report " + recipientId + "   ==";
      sendTextMessage(moderatorId, endMsg);
      isReportActivated = false;
      seqMessageOfReport = 0;
    }
  }
}

function sendMultipleImages(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId,
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            // subtitle: "Next-generation virtual reality",
            item_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQBta-66htflwi-K&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12602069_1350608345000055_9152154959326740480_n.jpg%3Foh%3D94a78537864e25e5b0c0067dfe89bc4a%26oe%3D59B5B9E8&_nc_hash=AQDXEZQ5Q2GI33IR",               
            image_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQBta-66htflwi-K&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12602069_1350608345000055_9152154959326740480_n.jpg%3Foh%3D94a78537864e25e5b0c0067dfe89bc4a%26oe%3D59B5B9E8&_nc_hash=AQDXEZQ5Q2GI33IR",
            // buttons: [{
            //   type: "web_url",
            //   url: "https://www.oculus.com/en-us/rift/",
            //   title: "Open Web URL"
            // }, {
            //   type: "postback",
            //   title: "Call Postback",
            //   payload: "Payload for first bubble",
            // }],
          }, {
            title: "touch",
            // subtitle: "Your Hands, Now in VR",
            // item_url: "https://www.oculus.com/en-us/touch/",               
            item_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQAdmID8qGcDGvMr&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12602128_118926911963432_2231322187007000576_n.jpg%3Foh%3D38530dcc484871d407b624653afa6f4b%26oe%3D599D9314&_nc_hash=AQD1N4yaX7CyCEqX",
            image_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQAdmID8qGcDGvMr&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12602128_118926911963432_2231322187007000576_n.jpg%3Foh%3D38530dcc484871d407b624653afa6f4b%26oe%3D599D9314&_nc_hash=AQD1N4yaX7CyCEqX",
            // buttons: [{
            //   type: "web_url",
            //   url: "https://www.oculus.com/en-us/touch/",
            //   title: "Open Web URL"
            // }, {
            //   type: "postback",
            //   title: "Call Postback",
            //   payload: "Payload for second bubble",
            // }]
          }, {
            title: "travel around the world",
            item_url: "https://scontent.xx.fbcdn.net/v/t34.0-0/p280x280/20370750_1737704382924432_1874631364_n.jpg?_nc_ad=z-m&oh=14a01e3d69fe582886af28d900cb6f6f&oe=597B0AD8",            
            image_url: "https://scontent.xx.fbcdn.net/v/t34.0-0/p280x280/20370750_1737704382924432_1874631364_n.jpg?_nc_ad=z-m&oh=14a01e3d69fe582886af28d900cb6f6f&oe=597B0AD8",            
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

function sendList (recipientID) {
  const messageData = {
    recipient:{
      id: recipientID
    }, 
    message: {
      attachment: {
          type: "template",
          payload: {
              template_type: "list",
              elements: [
                  {
                      title: "Classic T-Shirt Collection",
                      image_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQA19xWlLrM2KJCK&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12533901_1815209992135564_2169362344549810176_n.jpg%3Foh%3Da41e288e5837475c8a5ee569d96b988d%26oe%3D59A15CCF&_nc_hash=AQBW1C_F4-NOsjtC",
                      subtitle: "See all our colors",
                      // default_action: {
                      //     type: "web_url",
                      //     url: "https://www.oculus.com/experiences/rift/866068943510454/",
                      //     messenger_extensions: false,
                      //     webview_height_ratio: "tall",
                      //     fallback_url: "https://www.oculus.com"
                      // },
                  },
                  {
                      title: "Classic White T-Shirt",
                      image_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQA19xWlLrM2KJCK&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12533901_1815209992135564_2169362344549810176_n.jpg%3Foh%3Da41e288e5837475c8a5ee569d96b988d%26oe%3D59A15CCF&_nc_hash=AQBW1C_F4-NOsjtC",
                      subtitle: "100% Cotton, 200% Comfortable",
                      // default_action: {
                      //     type: "web_url",
                      //     url: "https://www.oculus.com/experiences/rift/866068943510454/",
                      //     messenger_extensions: false,
                      //     webview_height_ratio: "tall",
                      //     fallback_url: "https://www.oculus.com"
                      // },
                  },
                  {
                      title: "Classic Blue T-Shirt",
                      image_url: "https://external.fkul3-1.fna.fbcdn.net/safe_image.php?d=AQA19xWlLrM2KJCK&url=https%3A%2F%2Fscontent.oculuscdn.com%2Fv%2Ft64.5771-25%2F12533901_1815209992135564_2169362344549810176_n.jpg%3Foh%3Da41e288e5837475c8a5ee569d96b988d%26oe%3D59A15CCF&_nc_hash=AQBW1C_F4-NOsjtC",
                      subtitle: "100% Cotton, 200% Comfortable",
                      // default_action: {
                      //     type: "web_url",
                      //     url: "https://www.oculus.com/experiences/rift/866068943510454/",
                      //     messenger_extensions: false,
                      //     webview_height_ratio: "tall",
                      //     fallback_url: "https://www.oculus.com"
                      // },
                  }],
              buttons: [
                  {
                      type: "web_url",
                      url: "https://www.facebook.com/imMeowMeowTheCat/", 
                      title: "Visit Page"
                    }
              ]  
          }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
