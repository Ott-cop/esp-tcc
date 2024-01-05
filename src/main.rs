
use std::sync::{Arc, Mutex};
use std::time::Duration;
use esp_idf_svc::hal::gpio::PinDriver;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::hal::reset::restart;
use esp_idf_svc::http::Method;
use esp_idf_svc::http::server::{EspHttpServer, HandlerError, Connection};
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::nvs::{EspNvsPartition, EspNvs, NvsCustom, EspCustomNvsPartition};
use esp_idf_svc::sys::vTaskDelay;
use esp_idf_svc::timer::EspTaskTimerService;
use esp_idf_svc::wifi::{EspWifi, AsyncWifi, ClientConfiguration, Configuration, AuthMethod};
use esp_idf_svc::{eventloop::EspSystemEventLoop, nvs::EspDefaultNvsPartition};
use std::result::Result::Err;
use futures::executor::block_on;
use json::JsonValue;
use log::info;

const SSID: &str = "Apollo_2.4G";
const PASSWORD: &str = "apollo_tplink*#";
const STACK_SIZE: usize = 12288;
const MAX_STR_LEN: usize = 300;


fn main() {
    esp_idf_svc::sys::link_patches();
    EspLogger::initialize_default();
    

    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();
    let timer_service = EspTaskTimerService::new().unwrap();

    let mut wifi = AsyncWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs)).unwrap(),
        sys_loop,
        timer_service
    ).unwrap();

    unsafe {
        esp_idf_svc::sys::esp_task_wdt_deinit();
        esp_idf_svc::sys::esp_wifi_set_ps(esp_idf_svc::sys::wifi_ps_type_t_WIFI_PS_NONE);
    } 
    let nvs_data_partition: EspNvsPartition<NvsCustom> = EspCustomNvsPartition::take("nvs_data").unwrap();

    let mut server = block_on(create_server(&mut wifi)).unwrap();

    let namespace = "memory_save";

    let nvs_data = Arc::new(Mutex::new(EspNvs::new(nvs_data_partition, namespace, true).unwrap()));

    let comp_tag = "comp_tag";
    let mut buffer_data: [u8; MAX_STR_LEN] = [0; MAX_STR_LEN];
    

    let data = json::object! { 
        comp_1: "".to_string(),
        comp_2: "".to_string(),
        comp_3: "".to_string(),
        comp_4: "".to_string(),
        comp_5: "".to_string(),
        comp_6: "".to_string(),
        comp_7: "".to_string(),
        comp_8: "".to_string(),
    };
    let data = data.dump();
    
    let mut value = String::new();
    let getvalue = nvs_data.lock().unwrap().get_str(comp_tag, &mut buffer_data);
    if getvalue.is_err() {
        println!("[!] Problem to obtain data of NVS...");
    } else {
        let getvalue = getvalue.unwrap();
        if getvalue.is_none() {
            println!("[+] Doesnt have data!");
            println!("[+] Setting default...");
            value = data;
            let _ = nvs_data.lock().unwrap().set_str(comp_tag, &value);
        } else {
            println!("[+] Success to obtain data!");
            value = getvalue.unwrap().to_string();
        }
    }

    let json_value = Arc::new(Mutex::new(json::parse(&value.trim_end_matches(char::from(0))).unwrap()));
    
    let json_value2 = json_value.clone();
    let comp_1 = Arc::new(Mutex::new(PinDriver::output(peripherals.pins.gpio2).unwrap()));
    let comp_2 = Arc::new(Mutex::new(PinDriver::output(peripherals.pins.gpio13).unwrap()));
    
    if json_value.lock().unwrap()["comp_1"] == JsonValue::String("on".to_string()) {
        comp_1.lock().unwrap().set_high().unwrap();
    } else {
         comp_1.lock().unwrap().set_low().unwrap();
    }
    if json_value.lock().unwrap()["comp_2"] == JsonValue::String("on".to_string()) {
        comp_2.lock().unwrap().set_high().unwrap();
    } else {
        comp_2.lock().unwrap().set_low().unwrap();
    }

    let nvs_storage = nvs_data.clone();
    let nvs_storage2 = nvs_data.clone();

    server.fn_handler("/", Method::Post, move |mut req| {
        let mut nvs_storage = nvs_storage.lock().unwrap();
        let mut json_value = json_value2.lock().unwrap();
        let mut buffer = [0u8; MAX_STR_LEN];
        req.read(&mut buffer).unwrap();       
        
        let mut comp_1 = comp_1.lock().unwrap();
        let mut comp_2 = comp_2.lock().unwrap();

        let json_data = String::from_utf8_lossy(&buffer);
        let json_data = json::parse(json_data.trim_end_matches(char::from(0)));
        if json_data.is_err() {
            return Result::Err(HandlerError::new("Problems to parse JSON"));
        }
        let json_data = json_data.unwrap();
        println!("json_value da data: {:?}", json_data);

        if json_data["comp_1"] == JsonValue::String("on".to_string()) {
            comp_1.set_high().unwrap();
            json_value["comp_1"] = JsonValue::String("on".to_string());
        } else if json_data["comp_1"] == JsonValue::String("off".to_string()) {
            comp_1.set_low().unwrap();
            json_value["comp_1"] = JsonValue::String("off".to_string());
        }
        if json_data["comp_2"] == JsonValue::String("on".to_string()) {
            comp_2.set_high().unwrap();
            json_value["comp_2"] = JsonValue::String("on".to_string());
        } else if json_data["comp_2"] == JsonValue::String("off".to_string()) {
            comp_2.set_low().unwrap();
            json_value["comp_2"] = JsonValue::String("off".to_string());
        }
        
        unsafe { esp_idf_svc::sys::vTaskDelay(10) };
        let _ = nvs_storage.set_str(comp_tag, json_value.dump().trim_end_matches(char::from(0)));
        unsafe { esp_idf_svc::sys::vTaskDelay(10) };
        let mut response_buffer: [u8; MAX_STR_LEN] = [0; MAX_STR_LEN];
        
        unsafe { esp_idf_svc::sys::vTaskDelay(10) };
        
        let response_data = nvs_storage.get_str(comp_tag, &mut response_buffer).unwrap().unwrap();
        unsafe { esp_idf_svc::sys::vTaskDelay(10) };
        
        let initiate = req.connection().initiate_response(200, None, &[("Content-Type", "application/json")]);
        match initiate {
            Ok(_) => {println!("The message was successfully sent!")},
            Err(_) => {println!("There was a problem sending the message!")}
        }
        req.connection().write(response_data.trim_end_matches(char::from(0)).as_bytes()).unwrap();
       
        Result::Ok(())
        
    }).unwrap()
    .fn_handler("/", Method::Get, move |mut req| {
        
        
        let nvs_storage = nvs_storage2.lock().unwrap();
        unsafe { esp_idf_svc::sys::vTaskDelay(10) };
        let mut response_buffer = [0u8; MAX_STR_LEN];
        let response_data = nvs_storage.get_str(comp_tag, &mut response_buffer).unwrap().unwrap();
        unsafe { esp_idf_svc::sys::vTaskDelay(10) };
        
        println!("Value = {:?}", response_data);
        let initiate = req.connection().initiate_response(200, None, &[("Content-Type", "application/json")]);
        match initiate {
            Ok(_) => {println!("The message was successfully sent!")},
            Err(_) => {println!("There was a problem sending the message!")}
        }
        loop {
            let value = req.connection().write(response_data.trim_end_matches(char::from(0)).as_bytes());
            if value.is_ok() {
                break;
            }
        }
        
        Result::Ok(())

    }).unwrap();

   

    let ip_info = wifi.wifi().sta_netif().get_ip_info().unwrap();
    
    info!("Wifi DHCP info: {:?}", ip_info);
    

    loop {
        unsafe { vTaskDelay(10) }
        if !wifi.is_connected().unwrap() {
            println!("There was a problem with the WiFi connection");
            restart();
        }
        unsafe { vTaskDelay(10) }
    }
}

async fn create_server<'a>(wifi: &mut AsyncWifi<EspWifi<'static>>) -> Result<EspHttpServer<'a>, String> {
    let wifi_configuration: Configuration = Configuration::Client(ClientConfiguration {
        ssid: SSID.into(),
        password: PASSWORD.into(),
        ..Default::default()
    });        

    wifi.set_configuration(&wifi_configuration).unwrap();

    let _ = wifi.start().await;
    info!("Wifi started");

    let _ = wifi.connect().await;
    info!("Wifi connected");

    
    loop {
        let scan = wifi.get_configuration();
        println!("{:?}", scan);
        let compare = Configuration::Client(ClientConfiguration {
            ssid: SSID.into(),
            password: PASSWORD.into(),
            auth_method: AuthMethod::None,
            ..Default::default()
        });
        if scan.unwrap() == compare {
            restart();
        } else {
            break;
        }
    }

    let _ = wifi.wait_netif_up().await;
    info!("Wifi netif up");

    let server_configuration = esp_idf_svc::http::server::Configuration {
        stack_size: STACK_SIZE,
        session_timeout: Duration::MAX,
        ..Default::default()
    };
    Ok(EspHttpServer::new(&server_configuration).unwrap())
    
}

