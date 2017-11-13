# Web Push (VAPID) adapter for sly/notification-pusher

Web Push (VAPID) adapter for [sly/notification-pusher](https://github.com/Ph3nol/NotificationPusher)

[![StyleCI](https://styleci.io/repos/66535119/shield?branch=master)](https://styleci.io/repos/66535119)

## Installation

    $ composer require openpp/web-push-adapter

## Usage

    <?php
    
    // First, instantiate the manager and declare the adapter.
    $pushManager    = new \Sly\NotificationPusher\PushManager();
    $webPushAdapter = new \Openpp\WebPushAdapter\Adapter\Web(array(
        'publicKey'  => '/path/to/servers/public_key.pem',  // ECDSA public key path for the VAPID
        'privateKey' => '/path/to/servers/private_key.pem', // ECDSA private key path for the VAPID
    ));
    
    // Set the device(s) to push the notification to.
    $device1 = new \Sly\NotificationPusher\Model\Device();
    $device1->setToken('https://updates.push.services.mozilla.com/wpush/v2/abc...') // endpoint for firefox
            ->setParameters(array(
                'publicKey' => 'BJe6mzZYL9nfT4GGH4abkLLTirge...', // user agent public key
                'authToken' => '4dAIFNwyT3-wZ58wB09T9Q' // user agent authentication secret
              ));
    
    $device2 = new \Sly\NotificationPusher\Model\Device();
    $device2->setToken('https://fcm.googleapis.com/fcm/send/abc...') // endpoint for chrome
            ->setParameters(array(
                'publicKey' => 'BPh5gqtHha5G3XQD4hBslHBcVbKgh...',
                'authToken' => 'W9jjJNUXOZXnFhCfKwOYhQ'
              ));
     // ...
    
    $devices = new Sly\NotificationPusher\Collection\DeviceCollection(array(
        $device1,
        $device2,
        // ...
    ));
    
    // Then, create the push skel.
    $message = new Sly\NotificationPusher\Model\Message('This is an example.', array(
        'title' => 'Web Push Test',
    ));
    
    // Finally, create and add the push to the manager, and push it!
    $push = new Sly\NotificationPusher\Model\Push($webPushAdapter, $devices, $message);
    $pushManager->add($push);
    $pushManager->push();

## Service Worker example

This adapter sends the message as JSON. The key of message text is `"message"`.

    self.addEventListener('push', function(event) {
      var obj = event.data.json();
    
      var title = obj.title;
      var message = obj.message;
      var icon = 'push-icon.png';
      var tag = 'push';
    
      event.waitUntil(self.registration.showNotification(title, {
        body: message,
        icon: icon,
        tag: tag
       }));
     });
