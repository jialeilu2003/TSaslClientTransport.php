<?php
/**
* @file:    TSaslClientTransport.php
* @brief: 
*   基于hbase+kerberos+thrift 接口方案,实现依赖krb5扩展，实现sasl+gssapi的kerberos认证
*
*  参考:
*  python  版本实现：
*   /usr/lib/python2.7/site-packages/puresasl/mechanisms.py
*   /usr/lib/python2.7/site-packages/puresasl/client.py
*   /usr/lib64/python2.7/site-packages/thrift/transport/TTransport.py
*  https://www.ietf.org/rfc/rfc2222.txt
*  http://web.mit.edu/kerberos/www/krb5-latest/doc/appdev/gssapi.html
*  https://github.com/pierrejoye/php-krb5
*  https://github.com/frohoff/jdk8u-dev-jdk/blob/master/src/share/classes/com/sun/security/sasl/gsskerb/GssKrb5Client.java
*
*/

/*
#kerberos 认证得thrift server
#sasl service name:hbase
$socket = new TSocket('host',9090);
$socket->setSendTimeout(10000); // Ten seconds (too long for production, but this is just a demo ;)
$socket->setRecvTimeout(20000); // Twenty seconds
#$transport = new TBufferedTransport($socket);
$transport = new TSaslClientTransport($socket,$servicename='hbase','GSSAPI','host');
$protocol = new TBinaryProtocol($transport);
$client = new HbaseClient($protocol);
$transport->open();
$tables = $client->getTableNames();
sort($tables);
foreach ($tables as $name) {
    echo( "  table found: {$name}\n" );
}
$transport->close();


/*
 * @package thrift.transport
 */

namespace Thrift\Transport;
use Thrift\Exception\TTransportException;

/**
 * @package thrift.transport
 */
class TSaslClientTransport extends TTransport {

    const START = 1;
    const OK = 2;
    const BAD = 3;
    const ERROR = 4;
    const COMPLETE = 5;

    /**
     * @var TTransport
     */
    protected $transport_;

    protected $wbuffer_, $rbuffer_;
    protected $service_;
    protected $krb5_gssapi_;
    protected $server_;

    public function __construct(TTransport $transport, $service = "", $mechanism = 'GSSAPI', $server='') {
        $this->transport_ = $transport;
        $this->wbuffer_ = '';
        $this->rbuffer_ = '';
        $this->service_ = $service;
        $this->server_ = $server;
        $this->mechanism_ = $mechanism;

        #kerberos v5 php exetion
        if(!extension_loaded('krb5')){
            throw new TTransportException("need krb5 extension!");
        }
        $this->krb5_gssapi_ = new \GSSAPIContext();
        $credetials = $this->krb5_gssapi_->inquireCredentials();
        if(!is_array($credetials) || !isset($credetials['name'])){
            throw new TTransportException("you need run kinit:kinit -k -t yourkeytab yourusername");
        }
    }

    /**
     * Whether this transport is open.
     *
     * @return boolean true if open
     */
    public function isOpen() {
        return $this->transport_->isOpen();
    }

    /**
     * Open the transport for reading/writing
     *
     * @throws TTransportException if cannot open
     */
    public function open() {
        if (!$this->isOpen()) {
            $this->transport_->open();
        }

        #gssapi start
        #GSSAPI step 1
        $this->send_sasl_msg(self::START, $this->mechanism_);
        $target = sprintf('%s/%s', $this->service_,$this->server_);
        $ret = $this->krb5_gssapi_->initSecContext($target,null,GSS_C_MUTUAL_FLAG,null,$output_token,$output_flags,$output_times);
        $gss_token_0 = $output_token; #GSS_C_MUTUAL_FLAG for auth 
        #echo sprintf("gssapi_init_sec_context:ret:%s\ttokenlen:%s\t%d\t%d\n",$ret,strlen($output_token),$output_flags,$output_times);
        $this->send_sasl_msg(self::OK, $gss_token_0);
        @list($status, $payload) = $this->recv_sasl_msg();
        $gss_token_1 = $payload;
        
        #GSSAPI step 2
        $ret = $this->krb5_gssapi_->initSecContext($target,$gss_token_1,NULL,null,$output_token,$output_flags,$output_times);
        #echo sprintf("gssapi_init_sec_context:ret:%s\ttokenlen:%s\t%d\t%d\n",$ret,strlen($output_token),$output_flags,$output_times);
        $gss_token_2 = $output_token;
        if(!$ret){
            throw new TTransportException("server return token not sec init!");
        }
        if(strlen($gss_token_2)!=0){
            #goto step 2
            #pass
            throw new TTransportException("gssapi init error,gss_token_2!");
        }
        #GSSAPI step 3,handshake final 
        $this->send_sasl_msg(self::OK, '');
        while(true){
            @list($status, $payload) = $this->recv_sasl_msg();
            #echo sprintf("%s\tlen:%s\t%s\n",$status,strlen($payload),base64_encode($payload));
            if( self::OK == $status ){
                #loop for client/server 
                #only once loop
                $ret = $this->krb5_gssapi_->unwrap($payload,$challenge);
                #echo sprintf("gssapi unwrap:ret:%s\t%s\n",$ret,$challenge);
                $ret = $this->krb5_gssapi_->wrap($challenge,$gss_out_token,true);
                #echo sprintf("gssapi wrap:ret:%s\tlen:%s\n",$ret,strlen($gss_out_token));
                $this->send_sasl_msg(self::OK, $this->sasl_process($gss_out_token));
            }else if( self::COMPLETE == $status){
                 
                break;
            }else{
                throw new TTransportException(sprintf("Bad SASL negotiation status: %d (%s)", $status,$payload));
            }

        } 
        return true;
    }
    function sasl_process($payload){
        return $payload;
    }
    /**
     * Close the transport.
     */
    public function close() {
        $this->transport_->close();
    }

    /**
     * Read some data into the array.
     *
     * @param int $len How much to read
     * @return string The data that has been read
     * @throws TTransportException if cannot read any more data
     */
    public function read($len) {
        if (strlen($this->rbuffer_) > 0) {
            $ret = substr($this->rbuffer_, 0, $len);
            $this->rbuffer_ = substr($this->rbuffer_, $len);
            return $ret;
        }

        $data = $this->transport_->readAll(4);
        $array = unpack('Nlength', $data);
        $length = $array['length'];

        $this->rbuffer_ = $this->transport_->readAll($length);
        $ret = substr($this->rbuffer_, 0, $len);
        $this->rbuffer_ = substr($this->rbuffer_, $len);
        return $ret;
    }

    /**
     * Writes the given data out.
     *
     * @param string $buf  The data to write
     * @throws TTransportException if writing fails
     */
    public function write($buf) {
        $this->wbuffer_ .= $buf;
    }

    public function flush() {
        $buffer = pack('N', strlen($this->wbuffer_)) . $this->wbuffer_;
        $this->send($buffer);
        $this->wbuffer_ = '';
    }

    public function send($buf) {
        $this->transport_->write($buf);
        $this->transport_->flush();
    }

    public function pack($str) {
        $data = explode(' ', $str);
        $args = array(null);
        $cnt = 0;

        foreach ($data as $v) {
            $v1 = str_split($v, 2);
            foreach ($v1 as $v2) {
                $args[] = hexdec($v2);
                $cnt++;
            }
        }
        $args[0] = str_repeat('C', $cnt);
        $ret = call_user_func_array('pack', $args);
        return $ret;
    }

    /**
     * @brief: sals send 通道 for thrift auth only
     *
        *
        * @param $status
        * @param $body
        *
        * @return 
     */
    function send_sasl_msg($status,$body){
        $buffer = pack('CN', $status, strlen($body)) . $body;
        #echo sprintf("send_sasl_msg:status:%d length:%d\n",$status, strlen($body));
        $this->transport_->write($buffer);
        $this->transport_->flush();
    }
    /**
        * @brief: sasl recv 通道 for thrif auth only
        *
        * @return 
     */
    function recv_sasl_msg(){
        $data = $this->transport_->readAll(5);
        $arr  = unpack('Cstatus/Nlength', $data);
        $length = $arr['length'];
        $status = $arr['status'];
        $payload = $this->transport_->readAll($length);
        #echo sprintf("recv_sasl_msg:status:%d length:%d\n",$status, $length);
        return array($status,$payload);

    }
}
