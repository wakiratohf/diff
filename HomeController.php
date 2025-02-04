<?php

namespace App\Http\Controllers;

use App\ConfigVpn;
use App\Helpers\Helper;
use App\Vpn;
use App\VpnHistory;
use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class HomeController extends Controller
{
    
    public function testGetPublicKey()
    {
        $privateKeyPath = '/etc/letsencrypt/live/vpnapimon.tohapp.com/privkey.pem';

        $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyPath));

        if ($privateKey === false) {
            die('Unable to load private key.');
        }
        $keyDetails = openssl_pkey_get_details($privateKey);

        $publicKey = $keyDetails['key'];

        echo "Public Key: \n" . $publicKey;
    }
    
    public function testDecryptVpnConfig()
    {
        $data = "AHSuZcDn0Zbb3No+KPVdGcesf8VKCaAxiDrK8w3F3D5T4KMecLd0p5WwbCC2enRhvpkC+q1MmviF
P+F8nUKUVqLWxIp0CgQYoE/TiHFuVjSkhmHHF0Q/0QLsAy/TyRiFRbq3pFV8hxQ/12OMDpcrndW7
AX5RTXcpkX8CgIPRAKaMxK7xqwht3rN0hqBqZ3IR5kpk/Ifsk1iwsFuEyvclYw==";
        $dataDecrypted = $this->decryptVpnConfigEC(decodeBase64($data));
        echo $dataDecrypted;
    }
    
    private function decodeBase64($base64String)
    {
        $decodedData = base64_decode($base64String, true);

        if ($decodedData === false) {
            return "Invalid Base64 input!";
        } else {
            return $decodedData;
        }
    }

    public function testDecrypt(Request $request)
    {
        $dataEncrypted = $this->decodeBase64($request->data);
        $keyAES = $this->decryptAESKey($request);
        $iv = $this->decodeBase64($request->iv);
        $decData = $this->decryptDataWithAES($dataEncrypted, $keyAES, $iv);
        echo $decData;
    }
    
    private function decryptVpnConfigEC($VpnconfigBase64){
        $key = '757CBB5C17489F3A040D646FD7267CC2';
        $iv = '1234567890ABCDEF';
        $dataDecodedBase64 = $this->decodeBase64($VpnconfigBase64);
        $config = openssl_decrypt(
            $dataDecodedBase64,
            'AES-256-CBC',
            $key,
            OPENSSL_RAW_DATA,   
            $iv
        );
        return $config;
    }
    
    private function decryptDataWithAESGCM($encryptedData, $aesKey, $iv, $tag) {
        $decryptedData = openssl_decrypt(
            $encryptedData,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $decryptedData;
    }

    private function decryptDataWithAES($encryptedData, $aesKey, $iv) {
        // Ensure the AES key and IV are in binary format (not base64 or hex)
        $key = $aesKey;
        $iv = $iv;

        $decryptedData = openssl_decrypt($encryptedData, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        return $decryptedData;
    }
    
    function encryptData($sdk_v, $data, $aesKey, $tag) {
        if ($sdk_v >= 23) {
            return $this->encryptDataWithAESGCM($data, $aesKey, $tag);
        } else {            
            return $this->encryptDataWithAES($data, $aesKey);
        }
    }
    
    function encryptDataWithAESGCM($plainText, $aesKey, $tag) {
        $iv = random_bytes(16);

        $ciphertext = openssl_encrypt(
            $plainText,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,   
            $iv,
            $tag,
            "",
            16
        );

        if ($ciphertext === false) {
            throw new Exception('Encryption failed: ' . openssl_error_string());
        }

        // Trả về ciphertext, IV và tag dưới dạng mã hóa Base64
        return [
            base64_encode($ciphertext),
            base64_encode($iv),
            base64_encode($tag),
        ];
    }
    
    private function encryptDataWithAES($data, $aesKey) {
        $key = $aesKey;

        $iv = openssl_random_pseudo_bytes(16);

        $encryptedData = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        if ($encryptedData === false) {
            throw new Exception("Encryption failed");
        }
        $encryptedData = base64_encode($encryptedData);
        $encodedIV = base64_encode($iv);
        
        return [$encryptedData, $encodedIV, null];
        
        //$result = [
        //    'encryptedData' => base64_encode($encryptedData),
        //    'iv' => $encodedIV
        //];

        //$json = json_encode($result);
        
        //return $json;
    }

    
    
    public function decryptAESKey(Request $request)
    {
        $encryptedData = $this->decodeBase64($request->key);
//         // // $privateKeyPath = '/etc/letsencrypt/live/vpnapimon.tohapp.com/privkey.pem';

//         $key = "-----BEGIN PRIVATE KEY-----
// MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCr0ROoMnJamA9f
// GnvH0RDP2GcFf7lkK5ia/QRBTt99OVQfGvfjV2eHroV29wd5I5cJUcFcYveE9E1J
// PyjURRzh1Ed42jAqaQ57EZf9qX+u8oOZ/pEfCxWhG2nduRmVVVF9QYFPH5/k8flb
// JjGpt+utlSPUCxjekUY9/wFtdO93Bu+6vHoPLR/8ENlS2gB51XzTt4VCDemkLyWZ
// LJqOzFfTKRYRbQdfa/c8oDOdrIsvut9vNQ3Z7fdt4AuBocXi692dZbmkVzMPW5T9
// PRk75HjNCZU2EErDBfGVO91AFlgPVB/obxxtFNsxqpReLmMZzDKu8hxMxK31st8t
// SQXdpyO5AgMBAAECggEAEPGibaDj9Bkw0uEquc7dSJH/vuQUpVNDTm2LQOGFWrUP
// na2sKohRFmlYkh3UZ9bhqzKbzf+Yh00MXh/TZ/OU4JRto/Zob5ZCrlJS2dogVGFo
// JwSazSPrsyKf8xSw+DAcxCx0kxf8TbirLZj7ptATdt/RU7Twc+qBsdV3D5NLlkI4
// dFP99BHXZz1fM2JB4ISuwF0CqdFZz9hoB6Tq5NbempePV8Pm6yjrh2UH5FwG3FSl
// /tUA2jWfMS7st12xJNUggOtyqKez5C5AnrIACzS2EZWkTaWh4g6zY6f8dRNBOvDC
// 8QcQ7E263M6sQdnu7ZnKKB/TBQ/1yVnQ+WrJkjWcgQKBgQDbHIaGFbuMgLBIps13
// +/Taqq01RrxubUHbDjg5SbzJUNqFnq4k0OVqOAviT8UMLJN58VQb9unmGc8iY3NA
// Q56mgQdVcgO6TzDoRX+g+DqvLAdgIaW+QSbkGHa6y73jtn+X6Cd8fCFOlLAjc5W5
// vn8W2dmeHj2sz25ZNTX6pgrq8QKBgQDIvjKxoAMf21yB6Dz3Sj5M9Qqq+Q9Y3WZD
// 7QgBWAD2bXcqy71kb46Qfbl143mmDb/Nm4v0QUTkvDJEK4OftF0LxokbllPEVNFS
// fO8msvALh0YGNabQfZH+TXXzFBCW9V6d38yZCM91ONKhYN1Qh5ixwo8UbWOto5wW
// nadsdcp1SQKBgBkrJaixRmHVRmqR/ngR0QZtJIhCH9LvaeknsP2jorPdPbyrhYVl
// GXUiCvtr/k5vsGEJf4fWzPdJb6mbktmG6uplV9pQxmzYO93yXb63xMXqYM6CDu/T
// vAvnY3wBe0Z06CMi36ZE++5y1ei8li5H24FcdMrc3mjDSwGkQxcPi6GBAoGAIC72
// G6omthXKJ/2ewJrDkDz8/9o8Tqf4PE2lKen9BYUZROAzNgX4mku9zxuwJiIwLPuS
// HY/VRsKxYGKFkLYu8LNcyfJ47ZIXmRz0joTDnWWLoXU6kFSBcn7iuRzvZ/Rgvfji
// aWqTMBzzD/JiqQWEQoOJwuGiyHThknKmI+pikhkCgYEAv1Ati6GcQAGTaL4IEL8L
// cthZbzgAEXcxkTDPtGKuafIWT7rgksd99eTnGVszVvJaE0oFC+h62H63Jr3TLxUK
// gWOWGD0D178sda4Jtw14FJTWdLUoqp2zyszjsmfRBnKbN19CTu/ix/qNHXJZ7pnp
// r5ooA9lrf7A+Kgf6kiEM1kU=
// -----END PRIVATE KEY-----";
//         $decodedKey = '';
//         $decryptionSuccess = openssl_private_decrypt(
//             $encryptedData,
//             $decodedKey,
//             $key,
//             OPENSSL_PKCS1_PADDING
//         );
        //return $decodedKey;
        return $this->decodeBase64("qjtkdCMu2tNkyF+7avX/V8gGMX31at6r+tf3A3FiGUg=");
    }
    
    // public function getListVpnEC(Request $request)
    // {
    //     $listVpn = Vpn::where('online', 1)->where('test_vpn_server', 0)->get();
    //     $msg = 'OK!';
    //     foreach ($listVpn as $vpn) {
    //         if ($vpn->max_connection == 0) {
    //             $vpn->quality = 100;
    //         } else {
    //      //$vpn->quality = 100 - ((int)($vpn->current_connection * 100 / $vpn->max_connection));
    //      $vpn->quality = 100 - ((int)($vpn->cpu));
    //         }
    //     }
    //     $response = [
    //         'code' => 0,
    //         'message' => $msg,
    //         'data' => $listVpn
    //     ];
        
    //     $resJson = json_encode($response);
    //     $keyAES = $this->decryptAESKey($request);
    //     list($encryptedData, $encodedIV) = $this->encryptDataWithAES($resJson, $keyAES);
        
        
    //     return response()->json([
    //         'encryptedData' => base64_encode($encryptedData),
    //         'iv' => $encodedIV
    //     ], 200);
    // }

    public function getListVpnEC(Request $request)
    {
        $listVpn = Vpn::where('online', 1)->where('test_vpn_server', 0)->get();
        $msg = 'OK!';
        foreach ($listVpn as $vpn) {
            if ($vpn->max_connection == 0) {
                $vpn->quality = 100;
            } else {
            //$vpn->quality = 100 - ((int)($vpn->current_connection * 100 / $vpn->max_connection));
            $vpn->quality = 100 - ((int)($vpn->cpu));
            }
        }

        // Tạo phản hồi JSON
        $response = [
            'code' => 0,
            'message' => $msg,
            'data' => $listVpn
        ];

        $resJson = json_encode($response);
        $keyAES = $this->decryptAESKey($request);


        $tag = $this->decodeBase64($request->tag);
        list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

        return response()->json([
            'encryptedData' => $encryptedData,
            'iv' => $encodedIV,
            'tag' => $tagRes
        ], 200);
    }
    
    public function getListVpn(Request $request)
    {
        $listVpn = Vpn::where('online', 1)->where('test_vpn_server', 0)->get();
        $msg = 'OK!';
        foreach ($listVpn as $vpn) {
            if ($vpn->max_connection == 0) {
                $vpn->quality = 100;
            } else {
            //$vpn->quality = 100 - ((int)($vpn->current_connection * 100 / $vpn->max_connection));
            $vpn->quality = 100 - ((int)($vpn->cpu));
            }
        }
        return response()->json([
            'code' => 0,
            'message' => $msg,
            'data' => $listVpn
        ], 200);
    }

    public function getListVpnForBackend()
    {
        $listVpn = Vpn::all();
        $msg = 'OK!';
        foreach ($listVpn as $vpn) {
            if ($vpn->max_connection == 0) {
                $vpn->quality = 100;
            } else {
            //$vpn->quality = 100 - ((int)($vpn->current_connection * 100 / $vpn->max_connection));
            $vpn->quality = 100 - ((int)($vpn->cpu));
            }
        }
        return response()->json([
            'code' => 0,
            'message' => $msg,
            'data' => $listVpn
        ], 200);
    }

    public function getVpnDataChart(Request $request)
    {
        $data = VpnHistory::where('vpn_id', $request->id)
                          ->orderBy('datetime', 'desc')
                          ->get();

        // Trả về dữ liệu dưới dạng JSON
        return response()->json([
            'labels' => $data->pluck('datetime'),
            'connections' => $data->pluck('connections'),
            'cpu' => $data->pluck('cpu'),
            'ram' => $data->pluck('ram'),
        ]);
    }

    public function getVpn(Request $request)
    {
        $vpn = Vpn::where('id', $request->id)->first();
        if ($vpn == null) {
            $msg = 'Cant find vpn with id ' . $request->id;
            return response()->json([
                'code' => 404,
                'message' => $msg,
            ], 200);
        }
        $msg = 'OK!';
    //$vpn->quality = 100 - ((int)($vpn->current_connection * 100 / $vpn->max_connection));
    if ($vpn->max_connection == 0) {
            $vpn->quality = 100;
        } else {
        //$vpn->quality = 100 - ((int)($vpn->current_connection * 100 / $vpn->max_connection));
        $vpn->quality = 100 - ((int)$vpn->cpu);
        }
        return response()->json([
            'code' => 0,
            'message' => $msg,
            'data' => $vpn
        ], 200);
    }

    public function updateStatusVpn()
    {
        $listvpn = Vpn::where('online', 0)->select('id')->get()->toArray();
        ConfigVpn::whereIn('vpn_id', $listvpn)->delete();
        $listconfig = ConfigVpn::whereIn('vpn_id', $listvpn)->get();
        return response()->json([
            'code' => 200,
            'message' => $listconfig
        ], 200);
    }

    public function getConfigEC(Request $request)
    {
        $dataEncrypted = $this->decodeBase64($request->data);
        $keyAES = $this->decryptAESKey($request);
        $iv = $this->decodeBase64($request->iv);
        $tag = $this->decodeBase64($request->tag);
        $decData = "";
        if ($request->sdk_v >= 23) {
            $decData = $this->decryptDataWithAESGCM($dataEncrypted, $keyAES, $iv, $tag);
        } else {            
            $decData = $this->decryptDataWithAES($dataEncrypted, $keyAES, $iv);
        }
        
        //$decData = $this->decryptDataWithAES($dataEncrypted, $keyAES, $iv);
        $data = json_decode($decData, true);
        
        $msg = '';
        $device_id = $data['device_id'];
        $vpn_id = $data['vpn_id'];
        $order_id = null;

        if (!empty($data['order_id'])) {
            $order_id = $data['order_id'];
        }
        
        if ($order_id != null) {
            $order = User::where("order_id", $order_id)->first();
            if ($order == null) {
                $msg = 'subscription not exits on server';
                $response = [
                    'code' => 409,
                    'message' => $msg
                ];
                $resJson = json_encode($response);
                //$keyAES = $this->decryptAESKey($request);


                // // Mã hóa dữ liệu JSON bằng AES
                list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

                return response()->json([
                    'tag' => $tagRes,
                    'encryptedData' => $encryptedData,
                    'iv' => $encodedIV
                ], 200);
            }
            if ($order->endSub == 1) {
                $msg = 'Subscription is end  ';
                
                $response = [
                    'code' => 408,
                    'message' => $msg
                ];
                $resJson = json_encode($response);
                //$keyAES = $this->decryptAESKey($request);


                // // Mã hóa dữ liệu JSON bằng AES
                list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

                return response()->json([
                    'tag' => $tagRes,
                    'encryptedData' => $encryptedData,
                    'iv' => $encodedIV
                ], 200);
                
            }
        }
        $vpn = Vpn::where('id', $vpn_id)->first();
        if ($vpn == null) {
            $msg = 'Cant find vpn with id ' . $vpn_id;
            $response = [
                'code' => 404,
                'message' => $msg
            ];
            $resJson = json_encode($response);
            //$keyAES = $this->decryptAESKey($request);


            // // Mã hóa dữ liệu JSON bằng AES
            list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

            return response()->json([
                'tag' => $tagRes,
                'encryptedData' => $encryptedData,
                'iv' => $encodedIV
            ], 200);
        
        }

        $nameProfile = $vpn->host_name . 'free';
        if ($vpn->vpn_type == 1) {
            $nameProfile = $device_id;
            if (!$this->checkToken($order_id)) {
                $msg = "Token empty or end subscription";
                
                $response = [
                    'code' => 408,
                    'message' => $msg
                ];
                $resJson = json_encode($response);
                //$keyAES = $this->decryptAESKey($request);


                // // Mã hóa dữ liệu JSON bằng AES
                list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

                return response()->json([
                    'tag' => $tagRes,
                    'encryptedData' => $encryptedData,
                    'iv' => $encodedIV
                ], 200);
            }
        }
        $vpnConfig = new ConfigVpn;
        if ($vpn->vpn_type == 0) {
            $vpnConfig = ConfigVpn::where('order_id', 'like', $nameProfile)->where('vpn_id', 'like', $vpn_id)->first();
            if ($vpnConfig == null) {
                $response = $this->createConnectionVpn($vpn->ip, $nameProfile, $vpn->vpn_type);
                $code = $response['code'];
                if ($code == 0) {
                    $vpnConfig = new ConfigVpn;
                    $vpnConfig->order_id = $nameProfile;
                    $vpnConfig->vpn_id = $vpn_id;
                    $vpnConfig->config_data = $response['data']['configData'];
                    $vpnConfig->status = 0;
                    $vpnConfig->save();
                } else {
                    $msg = 'create profile with token ' . $nameProfile . ' fail';
                    $response = [
                        'code' => 405,
                        'message' => $msg
                    ];
                    $resJson = json_encode($response);
                    //$keyAES = $this->decryptAESKey($request);


                    // // Mã hóa dữ liệu JSON bằng AES
                    list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

                    return response()->json([
                        'tag' => $tagRes,
                        'encryptedData' => $encryptedData,
                        'iv' => $encodedIV
                    ], 200);
                    
                }
            }
        } else {
            $vpnConfig = ConfigVpn::where('order_id', $order_id)->where('vpn_id', $vpn_id)->where('device_id', $device_id)->first();
            if ($vpnConfig == null) {
                $response = $this->createConnectionVpn($vpn->ip, $nameProfile, $vpn->vpn_type);
                $code = $response['code'];
                if ($code == 0) {
                    ConfigVpn::where('order_id', $order_id)->update(['status' => 0]);
                    $vpnConfig = new ConfigVpn;
                    $vpnConfig->order_id = $order_id;
                    $vpnConfig->vpn_id = $vpn_id;
                    $vpnConfig->device_id = $device_id;
                    $vpnConfig->config_data = $response['data']['configData'];
                    $vpnConfig->status = 1;
                    $vpnConfig->save();
                } else {
                    $msg = 'create profile with token ' . $nameProfile . ' fail';
                    $response = [
                        'code' => 405,
                        'message' => $msg
                    ];
                    $resJson = json_encode($response);
                    //$keyAES = $this->decryptAESKey($request);


                    // // Mã hóa dữ liệu JSON bằng AES
                    list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

                    return response()->json([
                        'tag' => $tagRes,
                        'encryptedData' => $encryptedData,
                        'iv' => $encodedIV
                    ], 200);
                }
            }
        }
        $data = new ConfigVpn;
        //$data->config_data = $vpnConfig->config_data;
        $data->config_data = $this->decryptVpnConfigEC($vpnConfig->config_data);
        
        $msg = "Get config success";
        
        // Tạo phản hồi JSON
        $response = [
            'code' => 0,
            'message' => $msg,
            'data' => $data
        ];

        $resJson = json_encode($response);
        //$keyAES = $this->decryptAESKey($request);


        // // Mã hóa dữ liệu JSON bằng AES
        list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

        return response()->json([
            'tag' => $tagRes,
            'encryptedData' => $encryptedData,
            'iv' => $encodedIV
        ], 200);

    }
    
    public function getConfig(Request $request)
    {
        $msg = '';
        $device_id = $request->device_id;
        $vpn_id = $request->vpn_id;
        $order_id = $request->order_id;
        if ($order_id != null) {
            $order = User::where("order_id", $order_id)->first();
            if ($order == null) {
                $msg = 'subscription not exits on server';
                return response()->json([
                    'code' => 409,
                    'message' => $msg
                ], 200);
            }
            if ($order->endSub == 1) {
                $msg = 'Subscription is end  ';
                return response()->json([
                    'code' => 408,
                    'message' => $msg
                ], 200);
            }
        }
        $vpn = Vpn::where('id', $vpn_id)->first();
        if ($vpn == null) {
            $msg = 'Cant find vpn with id ' . $vpn_id;
            return response()->json([
                'code' => 404,
                'message' => $msg,
            ], 200);
        }

        $nameProfile = $vpn->host_name . 'free';
        if ($vpn->vpn_type == 1) {
            $nameProfile = $device_id;
            if (!$this->checkToken($order_id)) {
                $msg = "Token empty or end subscription";
                return response()->json([
                    'code' => 408,
                    'message' => $msg
                ], 200);
            }
        }
        $vpnConfig = new ConfigVpn;
        if ($vpn->vpn_type == 0) {
            $vpnConfig = ConfigVpn::where('order_id', 'like', $nameProfile)->where('vpn_id', 'like', $vpn_id)->first();
            if ($vpnConfig == null) {
                $response = $this->createConnectionVpn($vpn->ip, $nameProfile, $vpn->vpn_type);
                $code = $response['code'];
                if ($code == 0) {
                    $vpnConfig = new ConfigVpn;
                    $vpnConfig->order_id = $nameProfile;
                    $vpnConfig->vpn_id = $vpn_id;
                    $vpnConfig->config_data = $response['data']['configData'];
                    $vpnConfig->status = 0;
                    $vpnConfig->save();
                } else {
                    $msg = 'create profile with token ' . $nameProfile . ' fail';
                    return response()->json([
                        'code' => 405,
                        'message' => $msg
                    ], 200);
                }
            }
        } else {
            $vpnConfig = ConfigVpn::where('order_id', $order_id)->where('vpn_id', $vpn_id)->where('device_id', $device_id)->first();
            if ($vpnConfig == null) {
                $response = $this->createConnectionVpn($vpn->ip, $nameProfile, $vpn->vpn_type);
                $code = $response['code'];
                if ($code == 0) {
                    ConfigVpn::where('order_id', $order_id)->update(['status' => 0]);
                    $vpnConfig = new ConfigVpn;
                    $vpnConfig->order_id = $order_id;
                    $vpnConfig->vpn_id = $vpn_id;
                    $vpnConfig->device_id = $device_id;
                    $vpnConfig->config_data = $response['data']['configData'];
                    $vpnConfig->status = 1;
                    $vpnConfig->save();
                } else {
                    $msg = 'create profile with token ' . $nameProfile . ' fail';
                    return response()->json([
                        'code' => 405,
                        'message' => $msg
                    ], 200);
                }
            }
        }
        $data = new ConfigVpn;
        $data->config_data = $vpnConfig->config_data;
        $msg = "Get config success";
        return response()->json([
            'code' => 0,
            'message' => $msg,
            'data' => $data
        ], 200);
    }

    public function updateStatusPublishVpn(Request $request)
    {
        $vpn_id = $request->vpn_id;
        $status = $request->status;
        if ($status < 0 || $status > 1) {
            return response()->json([
                'code' => 400,
                'message' => 'value status not allow'
            ], 200);
        }
        $vpn = Vpn::where('id', $vpn_id)->first();
        if ($vpn == null) {
            return response()->json([
                'code' => 401,
                'message' => 'vpn not found'
            ], 200);
        }
        $msg = '';
        if ($vpn->test_vpn_server == $status) {
            if ($status == 1) {
                $msg = "is unpublish";
            } else {
                $msg = "is publish";
            }
            return response()->json([
                'code' => 200,
                'message' => 'vpn ' . $msg
            ], 200);
        }
        $vpn->test_vpn_server = $status;
        $vpn->save();
        if ($status == 0) {
            $msg = 'publish vpn success';
        } else {
            $msg = 'unpublish vpn success';
        }
        return response()->json([
            'code' => 200,
            'message' => $msg
        ], 200);
    }

    public function checkToken($token)
    {
        if ($token == null || $token == '' || empty($token)) {
            return false;
        }
        if ($token == 'use_are_vip_user') {
            return true;
        }
        return true;

    }

    public function checkSub(Request $request)
    {
        $device_id = $request->device_id;
        $order_id = $request->order_id;
        $token = $request->token;
        $msg = '';
        $code = 200;
        return response()->json([
            'code' => $code,
            'message' => $msg
        ], 200);
    }

    public function updateSubscriptionEC(Request $request)
    {
        $msg = 'Ok';
        $code = 200;
    //$order_id = $request->order_id;
    //
        $dataEncrypted = $this->decodeBase64($request->data);
        $keyAES = $this->decryptAESKey($request);
        $iv = $this->decodeBase64($request->iv);
        $tag = $this->decodeBase64($request->tag);
        $decData = "";
        if ($request->sdk_v >= 23) {
            $decData = $this->decryptDataWithAESGCM($dataEncrypted, $keyAES, $iv, $tag);
        } else {            
            $decData = $this->decryptDataWithAES($dataEncrypted, $keyAES, $iv);
        }
        //$decData = $this->decryptDataWithAES($dataEncrypted, $keyAES, $iv);
        $data = json_decode($decData, true);
        
        $token_pay = $data['token_pay'];
        $order_id = null;
        
        if(!empty($data['order_id'])) {
            $order_id = $data['order_id'];
    }

        $orderidInDb = User::where('order_id', $order_id)->first();
        if ($orderidInDb != null && $orderidInDb->endSub == 1) {
            return response()->json([
                'code' => 408,
                'message' => 'Subscription is end'
            ], 200);
        }
        //$token_pay = $request->token_pay;
        $data = json_encode($request->data);
        User::updateOrInsert(
            ['order_id' => $order_id]
            , ['token_pay' => $token_pay
                , 'data' => $data
                , 'endSub' => 0]
        );


        $response = [
            'code' => $code,
            'message' => $msg
        ];
        $resJson = json_encode($response);
        //$keyAES = $this->decryptAESKey($request);


        // // Mã hóa dữ liệu JSON bằng AES
        list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

        return response()->json([
            'tag' => $tagRes,
            'encryptedData' => $encryptedData,
            'iv' => $encodedIV
        ], 200);


        //return response()->json([
        //    'code' => $code,
        //    'message' => $msg
        //], 200);
    }

    public function updateSubscription(Request $request)
    {
        $msg = 'Ok';
        $code = 200;
        $order_id = $request->order_id;
        $orderidInDb = User::where('order_id', $order_id)->first();
        if ($orderidInDb != null && $orderidInDb->endSub == 1) {
            return response()->json([
                'code' => 408,
                'message' => 'Subscription is end'
            ], 200);
        }
        $token_pay = $request->token_pay;
        $data = json_encode($request->data);
        User::updateOrInsert(
            ['order_id' => $order_id]
            , ['token_pay' => $token_pay
                , 'data' => $data
                , 'endSub' => 0]
        );
//        $user = User::where('device_id', $device_id)->first();
//        if ($user == null) {
//            $user->device_id = $device_id;
//            $user->order_id = $order_id;
//            $user->token_pay = $token_pay;
//            $user->data = json_encode($data);
//            $user->save();
//        } else {
//            User::where('device_id', $device_id)->update();
//        }
        return response()->json([
            'code' => $code,
            'message' => $msg
        ], 200);
    }

    public function endSubscriptionEC(Request $request)
    {
        $msg = 'Ok';
        $code = 200;
        //$order_id = $request->order_id;
    //$device_id = $request->device_id;
    //
        $dataEncrypted = $this->decodeBase64($request->data);
        $keyAES = $this->decryptAESKey($request);
        $iv = $this->decodeBase64($request->iv);
        $tag = $this->decodeBase64($request->tag);
        $decData = "";
        if ($request->sdk_v >= 23) {
            $decData = $this->decryptDataWithAESGCM($dataEncrypted, $keyAES, $iv, $tag);
        } else {            
            $decData = $this->decryptDataWithAES($dataEncrypted, $keyAES, $iv);
        }
        $data = json_decode($decData, true);
        
        $device_id = $data['device_id'];
        $order_id = null;
        
        if(!empty($data['order_id'])) {
            $order_id = $data['order_id'];
    }

        if (empty($order_id)) {
            $configVpn = ConfigVpn::where('device_id', 'like', $device_id)->first();
            $order_id = $configVpn->order_id;
        }
        $configs = ConfigVpn::where('order_id', $order_id)->get();
        foreach ($configs as $config) {
            $vpnIp = Vpn::where('id', $config->vpn_id)->where('vpn_type', 1)->select('ip')->first();
            $resDel = $this->deleteConnectVpn($vpnIp->ip, $config->device_id);
            $resKill = $this->killConnectVpn($vpnIp->ip, $config->device_id);

        }
        User::where('order_id', $order_id)->update(['endSub' => 1]);
        ConfigVpn::where('order_id', $order_id)->delete();

        $response = [
            'code' => $code,
            'message' => $msg
        ];
        $resJson = json_encode($response);
        //$keyAES = $this->decryptAESKey($request);


        // // Mã hóa dữ liệu JSON bằng AES
        list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

        return response()->json([
            'tag' => $tagRes,
            'encryptedData' => $encryptedData,
            'iv' => $encodedIV
        ], 200);

        //return response()->json([
        //    'code' => $code,
        //    'message' => $msg
        //], 200);
    }

    public function endSubscription(Request $request)
    {
        $msg = 'Ok';
        $code = 200;
        $order_id = $request->order_id;
        $device_id = $request->device_id;
        if (empty($order_id)) {
            $configVpn = ConfigVpn::where('device_id', 'like', $device_id)->first();
            $order_id = $configVpn->order_id;
        }
        $configs = ConfigVpn::where('order_id', $order_id)->get();
        foreach ($configs as $config) {
            $vpnIp = Vpn::where('id', $config->vpn_id)->where('vpn_type', 1)->select('ip')->first();
            $resDel = $this->deleteConnectVpn($vpnIp->ip, $config->device_id);
            $resKill = $this->killConnectVpn($vpnIp->ip, $config->device_id);

        }
        User::where('order_id', $order_id)->update(['endSub' => 1]);
        ConfigVpn::where('order_id', $order_id)->delete();
        return response()->json([
            'code' => $code,
            'message' => $msg
        ], 200);
    }

    public function connectSuccessEC(Request $request)
    {
        $msg = 'Okay';
        $code = 0;
        //$vpn_id = $request->vpn_id;
        //$order_id = $request->order_id;
    //$device_id = $request->device_id;
    //
        $dataEncrypted = $this->decodeBase64($request->data);
        $keyAES = $this->decryptAESKey($request);
        $iv = $this->decodeBase64($request->iv);
        $tag = $this->decodeBase64($request->tag);
        $decData = "";
        if ($request->sdk_v >= 23) {
            $decData = $this->decryptDataWithAESGCM($dataEncrypted, $keyAES, $iv, $tag);
        } else {            
            $decData = $this->decryptDataWithAES($dataEncrypted, $keyAES, $iv);
        }
        $data = json_decode($decData, true);
        
        $msg = '';
        $device_id = $data['device_id'];
        $vpn_id = $data['vpn_id'];
        $order_id = null;
        
        if(!empty($data['order_id'])) {
            $order_id = $data['order_id'];
        }

        $currentConfig = ConfigVpn::where('order_id', $order_id)->where('device_id', $device_id)->where('status', 1)->first();

        if ($currentConfig != null && $currentConfig->status == 1) {
            $configs = ConfigVpn::where('order_id', $order_id)->where('device_id', 'not like', $device_id)->get();
            foreach ($configs as $config) {
                $vpnIp = Vpn::where('id', $config->vpn_id)->where('vpn_type', 1)->select('ip')->first();
                $resKill = $this->killConnectVpn($vpnIp->ip, $config->device_id);
                $resDel = $this->deleteConnectVpn($vpnIp->ip, $config->device_id);
            }
            ConfigVpn::where('order_id', $order_id)->where('device_id', 'not like', $device_id)->delete();
        } else {
            $msg = 'your config had kill by other device';
            $code = 410;
        }

        $response = [
            'code' => $code,
            'message' => $msg
        ];
        $resJson = json_encode($response);
        //$keyAES = $this->decryptAESKey($request);


        // // Mã hóa dữ liệu JSON bằng AES
        list($encryptedData, $encodedIV, $tagRes) = $this->encryptData($request->sdk_v, $resJson, $keyAES, $tag);

        return response()->json([
            'tag' => $tagRes,
            'encryptedData' => $encryptedData,
            'iv' => $encodedIV
        ], 200);
    }

    public function connectSuccess(Request $request)
    {
        $msg = 'Okay';
        $code = 0;
        $vpn_id = $request->vpn_id;
        $order_id = $request->order_id;
    $device_id = $request->device_id;
    //Log::info('connectSuccess.', ['order_id' => $order_id, 'device_id' => $request->device_id]);
        //kill and remove all config of other device
    $currentConfig = ConfigVpn::where('order_id', $order_id)->where('device_id', $device_id)->where('status', 1)->first();
    //$currentConfig = ConfigVpn::where('order_id', $order_id)->where('status', 1)->first();
        if ($currentConfig != null && $currentConfig->status == 1) {
            $configs = ConfigVpn::where('order_id', $order_id)->where('device_id', 'not like', $device_id)->get();
            foreach ($configs as $config) {
                $vpnIp = Vpn::where('id', $config->vpn_id)->where('vpn_type', 1)->select('ip')->first();
                //$resDel = $this->deleteConnectVpn($vpnIp->ip, $config->device_id);
        $resKill = $this->killConnectVpn($vpnIp->ip, $config->device_id);
        $resDel = $this->deleteConnectVpn($vpnIp->ip, $config->device_id);
        //Log::info('killConnectVpn.', ['ip' => $vpnIp->ip, 'device_id' => $config->device_id]);

            }
            ConfigVpn::where('order_id', $order_id)->where('device_id', 'not like', $device_id)->delete();
        } else {
            $msg = 'your config had kill by other device';
            $code = 410;
        }
        return response()->json([
            'code' => $code,
            'message' => $msg
        ], 200);
    }
//id
//host_name
//ip
//current_connectton
//max_connection
//city
//country
//vpn_type
    public function creatVpn(Request $request)
    {
        $id = $request->id;
        $vpnCurrentInDb = Vpn::where('id', $id)->first();
        Vpn::where('id', $id)->delete();
        $vpn = new Vpn;
        $vpn->id = $id;
        $vpn->host_name = $request->host_name;
        $vpn->ip = $request->ip;
        $vpn->current_connection = $request->current_connection;
        $vpn->max_connection = $request->max_connection;
        $city = $this->createCity($request->city);
        $vpn->city = $city;
        $vpn->country = $request->country;
        $vpn->vpn_type = $request->vpn_type;
        $vpn->lat = $request->lat;
        $vpn->lng = $request->lng;
        $vpn->cpu = 0;
        $vpn->ram = 0;
        $vpn->lastTimeSync = Helper::getTimeInMiliSecound();
        $vpn->online = 1;
        $vpn->status_vpn = $request->status_vpn;
        if ($vpnCurrentInDb != null) {
            $vpn->test_vpn_server = $vpnCurrentInDb->test_vpn_server;
        } else {
            $vpn->test_vpn_server = 1;
        }
        $vpn->save();
        return response()->json([
            'code' => 0,
            'message' => 'add vpn success',
            'data' => $vpn
        ], 200);
    }

    public function deleteProfile(Request $request)
    {
        $msg = 'Okay';
        $code = 0;
        $vpn_id = $request->vpn_id;
        $order_id = $request->order_id;
        $vpn = Vpn::where('id', $vpn_id)->first();
        if ($vpn == null) {
            $msg = 'Cant find vpn with id ' . $vpn_id;
            return response()->json([
                'code' => 404,
                'message' => $msg,
            ], 200);
        }
        $res = $this->deleteConnectVpn($vpn->ip, $order_id);
        $msgfromvpn = $res['msg'];
        $codefromvpn = $res['code'];
        if ($codefromvpn !== 200 || strpos($msgfromvpn, 'success') == false) {
            $code = 407;
            $msg = 'Delete connection ' . $order_id . ' from ' . $vpn->host_name . ' fail ';
        }
        return response()->json([
            'code' => $code,
            'message' => $msg,
        ], 200);

    }

    private function updateHostname($vpnIp, $hostname, $vpn_type)
    {
        $api = 'http://' . $vpnIp . ':5000/v1.0/tasks/update_hostname';
        $payload = json_encode(array(
                'hostname' => $hostname,
                'vpn_type' => $vpn_type
            )
        );
        $ch = curl_init($api);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        return json_decode($result, true);
    }

    public function updateNumberConnect(Request $request)
    {
        $vpn = Vpn::where('id', $request->id)->first();
    if ($vpn) {
        $currentTimestamp = Helper::getTimeInMiliSecound();
        $vpnHistoryLast = VpnHistory::where('vpn_id', $vpn->id)
                            ->orderBy('datetime', 'desc')
                            ->first();
        $recordedAt = $vpnHistoryLast ? $vpnHistoryLast->datetime : 0;
        if($request->cpu > 90 && (($currentTimestamp - $recordedAt) >= 1800000)) {
            $pythonScript = "python3  /var/www/html/send_msg_telegram_bot.py $vpn->city $vpn->ip  $request->cpu $request->ram  $request->current_connection $vpn->max_connection";
            if ($vpn->type == 1) {
                $pythonScript .= " --paid";
            }
            $output = shell_exec($pythonScript);
        }

            if (!$vpnHistoryLast || ($currentTimestamp - $recordedAt) >= 1800000) {
                $vpnHistory = new VpnHistory;
                $vpnHistory->vpn_id  = $vpn->id;
                $vpnHistory->hostname = $vpn->host_name;
                $vpnHistory->ip = $vpn->ip;
                $vpnHistory->datetime = Helper::getTimeInMiliSecound();
                $vpnHistory->cpu = $request->cpu;
        $vpnHistory->ram = $request->ram;
        $vpnHistory->connections  = $request->current_connection;
                $vpnHistory->save();
            }
            $vpn->current_connection = $request->current_connection;
            $vpn->cpu = $request->cpu;
            $vpn->ram = $request->ram;
            $vpn->lastTimeSync = Helper::getTimeInMiliSecound();
            $vpn->online = 1;
            $vpn->status_vpn = $request->status_vpn;
            $vpn->save();
            if ($vpn->host_name != $request->hostname) {
                $this->updateHostname($vpn->ip, $vpn->host_name, $vpn->vpn_type);
            }
            return response()->json([
                'code' => 0,
                'message' => 'update vpn success'
            ], 200);
        }
        return response()->json([
            'code' => 201,
            'message' => 'update vpn fail : can\' find vpn ' . $request->id
        ], 200);
    }

    private function killConnectVpn($vpnIp, $order_id)
    {
        $api = 'http://' . $vpnIp . ':5000/v1.0/tasks/killprofile';
        $payload = json_encode(array(
                'profilename' => $order_id
            )
        );
        $ch = curl_init($api);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        return json_decode($result, true);
    }

    private function deleteConnectVpn($vpnIp, $order_id)
    {
        $api = 'http://' . $vpnIp . ':5000/v1.0/tasks/removeprofile';
        $payload = json_encode(array(
                'profilename' => $order_id
            )
        );
        $ch = curl_init($api);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        return json_decode($result, true);
    }

    private function createConnectionVpn($vpn_id, $order_id, $vpn_type)
    {
        $api = 'http://' . $vpn_id . ':5000/v1.0/tasks/createprofile';
        $payload = json_encode(array(
                'profilename' => $order_id,
                'vpn_type' => $vpn_type,
            )
        );
        $ch = curl_init($api);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        return json_decode($result, true);
    }

    private function createCity($city)
    {
        $citys = Vpn::where('city', "like", $city . '%')->select('city')->get()->toArray();
        for ($i = 0; $i < count($citys); $i++) {
            if ($i >= count($citys)) {
                return $city . ($i + 1);
            } else {
//                dd($city . ($i + 1) . '-' . $citys[$i]['city']);
                if (strcasecmp($city . ($i + 1), $citys[$i]['city']) != 0) {
                    return $city . ($i + 1);
                } else {
                    continue;
                }
            }
        }
        return $city;
    }
}

