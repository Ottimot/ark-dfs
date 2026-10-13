use anyhow::{anyhow, Context, Result};
use std::{fs::{File, OpenOptions}, io::{self, BufReader, Write}, process::{Command, Stdio}, sync::{Arc, Mutex}};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, ServerName},
        crypto::aws_lc_rs,
        ClientConfig, KeyLog, RootCertStore,
    },
    TlsConnector,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, client};
use hyper::header::{HOST, CONTENT_TYPE, CONTENT_LENGTH, ACCEPT};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use http_body_util::Full;

use std::{collections::HashMap, fs, path::{Path, PathBuf}};
mod sha256_compression;
use sha256_compression::get_h_state;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce
};

use parser::Parser as circuit_generator;
use ark_bn254::{Bn254, Fr as Fr254};
use dfs::mpc::utils::generate_poly_shares_rss;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_ff::Zero;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter, log2};
use rayon::prelude::*;


use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystem}, 
};

use serde::Serialize;


#[derive(Serialize)]
struct McpRequest<'a> {
    jsonrpc: &'static str,
    id: &'a str,
    method: &'a str,
    params: McpParams<'a>,
}

#[derive(Serialize)]
struct McpParams<'a> {
    name: &'a str,
    arguments: CommandArgs<'a>,
}

#[derive(Serialize)]
struct CommandArgs<'a> {
    cmd: &'a str,
}


pub async fn send_ark<T, W>(stream: &mut W, value: &T) -> Result<()>
where
    T: CanonicalSerialize,
    W: AsyncWriteExt + Unpin,
{
    let mut payload = Vec::new();
    value.serialize_compressed(&mut payload)?; // or serialize_uncompressed

    let len = u32::try_from(payload.len()).map_err(|_| anyhow!("message too large"))?;
    stream.write_u32(len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}


const TRANSCRIPT_PATH: &str = "/app/transcript_example.txt";


fn run_string_circuit(
    transcript_path: &Path,
) -> Result<(PathBuf, PathBuf)> {
    let transcript_path = fs::canonicalize(transcript_path)
        .with_context(|| format!("missing transcript: {}", transcript_path.display()))?;
    let app_dir = transcript_path.parent().context("transcript needs a parent directory")?;
    let merkle_path = app_dir.join("merkle_tree/test_wildcard_pre.txt");
    anyhow::ensure!(transcript_path.is_file(), "missing transcript: {}", transcript_path.display());
    anyhow::ensure!(merkle_path.is_file(), "missing Merkle policy: {}", merkle_path.display());

    // Setup provides both files, which may be bind-mounted read-only.
    let circuit_path = app_dir.join("files/JRPC_complete_dynamic_optimized.arith");
    let layout_path = app_dir.join("files/input_layout_complete.txt");
    for path in [&circuit_path, &layout_path] {
        let metadata = fs::metadata(path)
            .with_context(|| format!("missing setup file: {}", path.display()))?;
        anyhow::ensure!(metadata.is_file() && metadata.len() > 0,
            "invalid setup file: {}", path.display());
    }

    let output_dir = app_dir.join("client-runtime/files");
    fs::create_dir_all(&output_dir)?;
    let input_path = output_dir.join("JRPC_complete_dynamic_randomid + pktnum_optimized.in");
    match fs::remove_file(&input_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("remove stale output {}", input_path.display())),
    }

    let status = Command::new("java")
        .current_dir(app_dir.join("input_generator"))
        .arg("JRPCInputGenerator")
        .arg("in")
        .arg(&layout_path)
        .arg(&transcript_path)
        .arg(&merkle_path)
        .arg("run_command")
        .arg("300")
        .arg(&input_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("launch JRPCInputGenerator")?;
    anyhow::ensure!(status.success(), "JRPCInputGenerator failed: {status}");
    let metadata = fs::metadata(&input_path)
        .with_context(|| format!("missing generated input: {}", input_path.display()))?;
    anyhow::ensure!(metadata.is_file() && metadata.len() > 0,
        "empty generated input: {}", input_path.display());

    Ok((circuit_path, input_path))
}

// AES-GCM encryption function
fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(iv);
    
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    
    Ok(ciphertext)
}

fn encrypt_handshake_records(
    encrypted_extensions: &[u8],
    certificate: &[u8], 
    certificate_verify: &[u8],
    handshake_finished: &[u8],
    iv_shs: &[u8],
    tk_shs: &[u8]
) -> Result<Vec<Vec<u8>>> {

    // Create the ptx array equivalent
    let ptx = vec![
        encrypted_extensions,
        certificate,
        certificate_verify, 
        handshake_finished
    ];
    
    // Initialize counter as zero-filled byte array with same length as iv_shs
    let mut counter = vec![0u8; iv_shs.len()];
    let mut ctx = Vec::new();
    
    // Process each handshake record
    for p in ptx {
        // XOR iv_shs with counter to create xorato
        let xorato: Vec<u8> = iv_shs.iter()
            .zip(counter.iter())
            .map(|(b1, b2)| b1 ^ b2)
            .collect();
        
        // Encrypt - this returns ciphertext + 16-byte auth tag
        let encrypted_full = encrypt_aes_gcm(p, &tk_shs, &xorato).unwrap();
        
        // Extract only the ciphertext portion (same length as input)
        // AES-GCM appends a 16-byte authentication tag, so we take all but the last 16 bytes
        let ciphertext_only = if encrypted_full.len() >= 16 {
            encrypted_full[..encrypted_full.len() - 16].to_vec()
        } else {
            encrypted_full // fallback, though this shouldn't happen
        };
        
        ctx.push(ciphertext_only);
        
        // Increment the last byte of counter
        if let Some(last) = counter.last_mut() {
            *last = last.wrapping_add(1);
        }
    }
    
    Ok(ctx)
}



fn read_file<P: AsRef<Path>>(path: P) -> std::io::Result<HashMap<String, Vec<u8>>>{
    let file = fs::read_to_string(path)?;
    let mut map = HashMap::new();
    let mut already_seen = Vec::<String>::new();
    
    let parse_hex = |hex_str: &str| -> Result<Vec<u8>, std::io::Error> {
        hex::decode(hex_str).map_err(|e| std::io::Error::new(
            std::io::ErrorKind::InvalidData, 
            format!("Failed to parse hex: {}", e)
        ))
    };
    
    for (_i,line) in file.lines().enumerate(){
        let line = line.trim();
        if line.is_empty(){
            continue;
        }

        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        if already_seen.contains(&key.to_string()){
            continue;
        }
        else{
            already_seen.push(key.to_string());
        }
        match key{
            "ec_pk_client_x_y" => {
                //need to split point x and y
                let mut hex_value = value.strip_prefix('"').unwrap_or(value);
                hex_value = hex_value.strip_prefix("04").unwrap_or(hex_value);
                let x = &hex_value[0..64];
                let y = &hex_value[64..128];
                map.insert("ec_pk_client_x".to_string(), parse_hex(x)?);
                map.insert("ec_pk_client_y".to_string(), parse_hex(y)?);
            },
            "ec_pk_server_x_y" => {
                //need to split point x and y
                let mut hex_value = value.strip_prefix('"').unwrap_or(value);
                hex_value = hex_value.strip_prefix("04").unwrap_or(hex_value);
                let x = &hex_value[0..64];
                let y = &hex_value[64..128];
                map.insert("ec_pk_server_x".to_string(), parse_hex(x)?);
                map.insert("ec_pk_server_y".to_string(), parse_hex(y)?);
            },
            _ => {
                //normal insert
                let value = value.trim_matches('"');
                map.insert(key.to_string(), parse_hex(value)?);
            }
        }
        
        
    }

    let tr_7 = map.get(&"full_transcript".to_string()).cloned();
    
    let tr_7_hex = hex::encode(&tr_7.clone().unwrap());
    let h_state = get_h_state(&tr_7_hex);
    eprintln!("H_state_tr7: {:?}", h_state);
    if let Ok(h_state_str) = h_state {
        // Parse the returned hex string back to Vec<u8>
        map.insert("H_state_tr7".to_string(), parse_hex(&h_state_str)?);
    
        
        
        let key = map.get(&"key_server".to_string()).cloned().unwrap();
        let iv = map.get(&"iv_server".to_string()).cloned().unwrap();


        match encrypt_aes_gcm(&tr_7.unwrap(), &key, &iv) {
            Ok(ct_7) => {
                map.insert("ct_7".to_string(), ct_7);
                eprintln!("Successfully encrypted tr_7 into ct_7");
            }
            Err(e) => {
                eprintln!("Failed to encrypt tr_7: {}", e);
            }
        }
    }


    

    //eprintln!("{:?}, {:?}", key, iv);


    Ok(map)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let f = File::open(path).map_err(|e| anyhow!("open certs {}: {}", path, e))?;
    let mut reader = BufReader::new(f);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("parse certs: {e:?}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certs found in {path}"));
    }
    Ok(certs)
}

fn make_client_config(roots: RootCertStore, keylog: Arc<dyn tokio_rustls::rustls::KeyLog>) -> anyhow::Result<ClientConfig> {
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![
        aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = vec![
        aws_lc_rs::kx_group::SECP256R1,
    ];

    let provider = Arc::new(provider);

    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();

    cfg.key_log = keylog;
    Ok(cfg)
}

// The Java circuit reads these eighteen fields by line number.
const TRANSCRIPT_FIELDS: [&str; 18] = [
    "psk", "ec_sk", "ec_pk_client_x", "ec_pk_client_y",
    "ec_pk_server_x", "ec_pk_server_y", "HS", "H2", "H7", "H3",
    "SF", "ch_sh", "ctx1", "ctx2", "ctx3", "ctx4", "ciphertext", "H_state_tr7",
];

fn write_transcript<W: Write>(dict: &HashMap<String, Vec<u8>>, writer: &mut W) -> Result<()> {
    let fields = TRANSCRIPT_FIELDS.iter()
        .map(|name| dict.get(*name).with_context(|| format!("missing transcript field: {name}")))
        .collect::<Result<Vec<_>>>()?;
    for value in fields {
        writeln!(writer, "{}", hex::encode(value)).context("write circuit transcript")?;
    }
    writer.flush().context("flush circuit transcript")?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct Logger{
    pub entries: Mutex<Vec<(String, Vec<u8>, Vec<u8>)>>,
}

impl KeyLog for Logger {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.entries
            .lock()
            .unwrap()
            .push((label.to_string(), client_random.to_vec(), secret.to_vec()));
        
        }
    }

/*
pub struct TLS_trascript{
    pub client_random: [u8; 32],
}
    */


#[tokio::main]
async fn main() -> Result<()> {
    // Usage: client <server_addr> <server_name> <ca_cert_pem>
    fs::remove_file("handshake_dump.txt").ok();
    //fs::remove_file("keylog.log").ok();
    //let mut _f = File::create("keylog.log")?;
    let args: Vec<String> = std::env::args().collect();
  
    let server_addr: String = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:8443".to_string());
    let server_name: String = args.get(2).cloned().unwrap_or_else(|| "localhost".to_string());
    let ca_path: String = args.get(3).cloned().unwrap_or_else(|| "certs/root-ca.pem".to_string());

    let name = ServerName::try_from(server_name.clone())
          .map_err(|e| anyhow!("Failed connection {}", e))?;

    let mut roots = RootCertStore::empty();
    for c in load_certs(&ca_path)? {
        roots.add(c).map_err(|e| anyhow!("add root cert: {e:?}"))?;
    }

    let keylog = Arc::new(Logger::default());
    let config = make_client_config(roots, keylog.clone())?;


    let connector = TlsConnector::from(Arc::new(config.clone()));

    let tcp = TcpStream::connect(server_addr).await?;
    let name = ServerName::try_from(server_name.clone()).map_err(|e| anyhow!("Bad server name: {}", e))?;
    

    let tls = connector.connect(name, tcp).await?;

    let mut dict = read_file("handshake_dump.txt")?;

    let client_random = dict.get(&"client_random".to_string()).cloned().unwrap_or_default();
    //let keylog_clone = keylog.clone();
   
    
   
    /*
    for (k,v) in dict.iter(){
        eprintln!("{}={}", k, hex::encode(v));
    }
    */
   
    // eprintln!("keylog : {:?}", config.key_log.clone());

    //eprintln!("Building HTTP request for server: {}", server_name);
    /* 
    let req = Request::builder()
        .method("POST")
        .uri("/function/run") 
        .header("Host", &server_name) 
        .body(Empty::<Bytes>::new())?;
    */
    //REQUEST FOR THE MCP

    let payload = McpRequest {
        jsonrpc: "2.0",
        id: "req-12345",
        method: "tools/call",
        params: McpParams {
            name: "run_command",
            arguments: CommandArgs {   
                cmd: "pippo",
            },
        },
    };

    let body = serde_json::to_vec(&payload)?; // JSON -> Vec<u8>

    //eprintln!("Request body length: {}", body.len());

    let req = Request::builder()
        .method("POST")
        .uri("/mcp") 
        .header(HOST, server_name.clone())
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Full::new(Bytes::from(body.clone())))?;


    let io = TokioIo::new(tls);
    let (mut sender, conn) = http1::handshake(io).await
        .map_err(|e| anyhow!("Failed to perform HTTP handshake: {}", e))?;
    
    // Build the complete HTTP message with headers and body
    let mut http_message = format!(
        "{} {} HTTP/1.1\r\n",
        req.method(),
        req.uri()
    );
    
    // Add headers
    for (name, value) in req.headers().iter() {
        http_message.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap_or("")));
    }
    
    // Add blank line to separate headers from body
    http_message.push_str("\r\n");

    //eprintln!("HTTP request headers len: {}", http_message.len());

    // Add body content
    let body_bytes = body.clone();
    
    let mut http_bytes_combined = http_message.into_bytes();
    http_bytes_combined.extend_from_slice(&body_bytes);
    
    //eprintln!("HTTP request that will be encrypted:\n{:?}", String::from_utf8_lossy(&http_bytes_combined));
    //eprintln!("HTTP request byte length: {}", http_bytes_combined.len());

    // Use the derived application traffic keys for encryption
    let key_app = dict.get(&"key_client_app".to_string()).cloned().unwrap();
    let iv_app = dict.get(&"iv_client_app".to_string()).cloned().unwrap();

    let encrypt = encrypt_aes_gcm(&http_bytes_combined, &key_app, &iv_app);
    
    //eprintln!("Ciphertext: {:?}", encrypt);
    //let key_u128 = u128::from_le_bytes(key_app);

    dict.insert("ciphertext".to_string(), encrypt.clone().unwrap_or_default());

    
    // Write simplified transcript file
    if let Ok(ref ciphertext) = encrypt {
        match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("simplified_transcript.txt") {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", hex::encode(ciphertext));
                let _ = writeln!(f, "{}", hex::encode(&key_app));
                let _ = writeln!(f, "{}", hex::encode(&iv_app));
                
                
                eprintln!("simplified_transcript.txt created successfully");
            }
            Err(e) => {
                eprintln!("Failed to create simplified_trascript.txt: {}", e);
            }
        }
    }

    let iv_shs = dict.get(&"iv_server".to_string()).cloned().unwrap_or_default();
    let tk_shs = dict.get(&"key_server".to_string()).cloned().unwrap_or_default();
    let encrypted_extensions = dict.get(&"encrypted_extensions".to_string()).cloned().unwrap_or_default();
    let certificate = dict.get(&"certificate".to_string()).cloned().unwrap_or_default();
    let certificate_verify = dict.get(&"certificate_verify".to_string()).cloned().unwrap_or_default();
    let handshake_finished = dict.get(&"handshake_finished".to_string()).cloned().unwrap_or_default();

    let ctx_vec = encrypt_handshake_records(
        &encrypted_extensions, 
        &certificate, 
        &certificate_verify, 
        &handshake_finished, 
        &iv_shs, 
        &tk_shs
    )?;

    eprintln!("{:?}", ctx_vec);

    // insert decoded hex strings into dict as Vec<u8>
    let keys = ["ctx1", "ctx2", "ctx3", "ctx4"];
    for (i, key) in keys.iter().enumerate() {
        if let Some(hexstr) = ctx_vec.get(i) {
            //let bytes = hex::decode(hexstr);
            dict.insert(key.to_string(), hexstr.clone());
        } else {
            dict.insert(key.to_string(), Vec::new());
        }
    }

    let transcript_path = Path::new(TRANSCRIPT_PATH);
    {
        let mut transcript = File::create(transcript_path)
            .with_context(|| format!("create transcript {}", transcript_path.display()))?;
        write_transcript(&dict, &mut transcript)?;
    }

    // Spawn the connection task
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("HTTP connection error: {}", e);
        }
    });

   
   
    let resp = sender.send_request(req).await.context("Failed to send HTTP request")?;
    eprintln!("HTTP - Status: {}", resp.status());
    
    let body_bytes = resp.into_body().collect().await?.to_bytes();
    //eprintln!("RESPONSE: {}", String::from_utf8_lossy(&body_bytes));

    
    // Generate session inputs using setup's circuit layout.
    let (circuit_path, input_path) = run_string_circuit(transcript_path)?;
    let c = circuit_generator::<Fr254>::new(
        circuit_path.to_string_lossy().into_owned(),
        input_path.to_string_lossy().into_owned(),
    );

    let cs = ConstraintSystem::<Fr254>::new_ref();

    c.clone().generate_constraints(cs.clone()).expect("generate_constraints failed");
    

    let (_, _, _, num_var, _, num_input, input, witness, _) = c.transform().expect("transform failed");
    //eprintln!("Parser andato");
    let mut z_eval = cfg_iter!(&input)
        .chain(&witness.clone())
        .copied()
        .collect::<Vec<Fr254>>();

    let z_vec = z_eval.clone();
    //z_eval.resize(pk.padded_num_var.pow2(), Fr254::zero());


    let mut witness_padded = vec![Fr254::zero(); num_input]; // Zeros for public input positions
    witness_padded.extend(witness.clone()); // Actual witness values
    
    // CORRECT: Only secret-share the WITNESS portion, not the public input
    let num_log = log2(num_var + num_input) as usize;
    let witness_poly = DenseMultilinearExtension::from_evaluations_vec(
    num_log,
        witness_padded.clone()
    );
    let mut rng = &mut ark_std::test_rng();
    let (witness_share_0, witness_share_1, witness_share_2) = generate_poly_shares_rss(&witness_poly, &mut rng);
    
    /*MODIFICA SETUP -> PRIMA SPLIT DI Z + SHARES, POI CALCOLO DI Z_A/B/C su shares */

    //let z_vec = split_vec(&z_vec, P_W);
    let z = DenseMultilinearExtension::from_evaluations_vec(num_log, z_vec.clone());

    eprintln!("created z!");
    let (z_share_0, z_share_1, z_share_2) = generate_poly_shares_rss(&z, &mut rng);

    eprintln!("Shares generated!");

    
    let mut socket_coord = TcpStream::connect("coordinator:8220").await?;

    // Send client_random (it's already a Vec<u8> from the TLS handshake)
    socket_coord.write_all(&client_random).await?;

    //invio a worker_1
    let mut socket_1 = TcpStream::connect("worker1:8220").await?;
    send_ark(&mut socket_1, &z_share_0).await?;
    send_ark(&mut socket_1, &z_share_1).await?;
    send_ark(&mut socket_1, &witness_share_0).await?;
    send_ark(&mut socket_1, &witness_share_1).await?;

    let mut socket_2 = TcpStream::connect("worker2:8220").await?;
    send_ark(&mut socket_2, &z_share_1).await?;
    send_ark(&mut socket_2, &z_share_2).await?;
    send_ark(&mut socket_2, &witness_share_1).await?;
    send_ark(&mut socket_2, &witness_share_2).await?;

    let mut socket_3 = TcpStream::connect("worker3:8220").await?;
    send_ark(&mut socket_3, &z_share_2).await?;
    send_ark(&mut socket_3, &z_share_0).await?;
    send_ark(&mut socket_3, &witness_share_2).await?;
    send_ark(&mut socket_3, &witness_share_0).await?;

    //let mut bytes = z_share_0.serialized_size(ark_serialize::Compress::Yes) + z_share_1.serialized_size(ark_serialize::Compress::Yes) + z_share_2.serialized_size(ark_serialize::Compress::Yes);
    //bytes = bytes*2;
    //eprintln!("Bytes total = {}", bytes);

   //FINE INVIO
   eprintln!("Shares sent to workers!");


    

    Ok(())
}

#[cfg(test)]
mod transcript_tests {
    use super::*;

    fn complete_transcript() -> HashMap<String, Vec<u8>> {
        TRANSCRIPT_FIELDS.iter().enumerate()
            .map(|(i, name)| (name.to_string(), vec![i as u8]))
            .collect()
    }

    #[test]
    fn transcript_preserves_the_java_line_order() {
        let mut output = Vec::new();
        write_transcript(&complete_transcript(), &mut output).unwrap();
        let expected = (0..18).map(|i| format!("{i:02x}\n")).collect::<String>();
        assert_eq!(String::from_utf8(output).unwrap(), expected);
    }

    #[test]
    fn missing_field_cannot_shift_the_remaining_lines() {
        let mut dict = complete_transcript();
        dict.remove("ec_sk");
        let mut output = Vec::new();
        let error = write_transcript(&dict, &mut output).unwrap_err();
        assert!(error.to_string().contains("ec_sk"));
        assert!(output.is_empty());
    }

    #[test]
    fn transcript_write_errors_are_reported() {
        // A fixed-size slice cannot hold the transcript.
        let mut output = [0u8; 1];
        assert!(write_transcript(&complete_transcript(), &mut &mut output[..]).is_err());
    }
}
