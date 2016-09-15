create table if not exists metadata (
        id integer primary key autoincrement,
        org_name text,
        email text,
        extra_contact_info text,
        last_report_id integer
);

create table if not exists adders (
        id integer primary key autoincrement,
        adder text,
        addername text,
        last_report_date integer
);

create table if not exists results (
        id integer primary key autoincrement,
        Version integer default 1,
        UserAgent text,
        Reported integer,
        ArrivalDate text,
        OriginalMailFrom text,
        OriginalRcptTo text,
        SourceIP text,
        DKIMSignature text,
        Subject text,
        Body text,
        SPFRecord text,
        DKIMRecord text,
        DMARCRecord text,
        SPFresult text,
        DKIMresult text,
        Alignresult text,
        Deliveryresult text,
        SPFreason text,
        DKIMreason text,
        DMARCreason text
);

