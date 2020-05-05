<?php


class Whois
{
  // taken from here: http://php720.com/snippet/11 
  // but doesn't contains all the whois servers we need
  public static function getInfo($domain)
  {
      $domain = strtolower(trim($domain));
      $domain = preg_replace('/^http:\/\//i', '', $domain);
      $domain = preg_replace('/^www\./i', '', $domain);
      $domain = explode('/', $domain);
      $domain = trim($domain[0]);

      // split the TLD from domain name
      $_domain = explode('.', $domain);
      $lst = count($_domain)-1;
      $ext = $_domain[$lst];

      $list = __DIR__ . '/list.json';
      if(!file_exists($list))
          self::parseList();
          
      $servers = json_decode(file_get_contents($list), TRUE);


      if(!isset($servers[$ext])) die('Error: No matching nic server found!');

      $nic_server = $servers[$ext];
      $output = '';

      // connect to whois server:
      if($conn = fsockopen ($nic_server, 43)) {
          fputs($conn, $domain."\r\n");
          while(!feof($conn)) $output .= fgets($conn,128);
          fclose($conn);
      } else {
          die('Error: Could not connect to '.$nic_server.'!');
      }

      return $output;
  }

  // https://github.com/whois-server-list/whois-server-list
  // Thanks to the guys from this repo, we've got the full whois-servers list
  // All we need is to parse it before using 
  public static function parseList()
  {
      $raw = file_get_contents('https://raw.githubusercontent.com/whois-server-list/whois-server-list/master/whois-server-list.xml');
      $xml = new \SimpleXMLElement($raw);
      $servers = [];
      foreach ($xml[0]->domain as $dmn)
      {
          if(isset($dmn->whoisServer))
          {
              $zone = get_object_vars($dmn->attributes()->name)[0];
              $host = get_object_vars($dmn->whoisServer->attributes()->host)[0];
              $servers[$zone] = $host;
          }
      }

      file_put_contents(__DIR__ . '/list.json', json_encode($servers));
  }
}
