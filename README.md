# iop-sdk-rust
Unofficial Rust AliExpress Open platform SDK (iop-sdk-rust)


## Example:

```rust
use std::collections::HashMap;
use dotenv_vault::dotenv;
use iop::{Iop, ApiName, RequestParameters, Result};


#[tokio::main]
async fn main() -> Result<()> {

    dotenv().expect(".env file not found");

    let app_key = std::env::var("APPKEY").expect("APPKEY variable dosn't exist");
    let secret = std::env::var("SECRET").expect("SECRET variable dosn't exist");

    let top_api = Iop::new(app_key.as_str(), secret.as_str());

    let url = "https://www.aliexpress.com/w/wholesale-삼성노트북.html"; // Aliexpress product url

    let mut request_parameters: RequestParameters = HashMap::new();
    request_parameters.insert("app_signature".to_string(), "asdasdasdsa".to_string());
    request_parameters.insert("promotion_link_type".to_string(), "0".to_string());
    request_parameters.insert("source_values".to_string(), url.to_string());
    request_parameters.insert("tracking_id".to_string(), "yourtracking_id".to_string());
    
    let response = top_api.request(ApiName::GenerateAffiliateLinks, Some(request_parameters)).await?;

    if response.status().is_success(){
        println!("is_success"); 
        println!("{:#?}", response.text().await?);  
    }

    Ok(())
}

```

## TODO:
- add more Apis
- Add more http methods
- Add sha256 sign method