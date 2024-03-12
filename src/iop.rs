// #![warn(dead_code)]
// #![warn(unused_assignments)]
// #![warn(unused_imports)]
// #![warn(private_in_public)]

use itertools::Itertools;
use std::collections::HashMap;
use std::fmt::Display;
use std::time::SystemTime;

use reqwest::{
    header::{HeaderValue, CACHE_CONTROL, CONNECTION, CONTENT_TYPE, USER_AGENT},
    ClientBuilder
};
use std::time::Duration;

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

//use ring::{digest, hmac};
//use data_encoding::BASE64;

// Create alias for HMAC-SHA256
type HmacMd5 = Hmac<Md5>;

#[allow(dead_code)]
const SIGN_METHOD_SHA256: &str = "sha256";
const SIGN_METHOD_MD5: &str = "md5";
const SIGN_METHOD_HMAC: &str = "hmac";

const SYSTEM_GENERATE_VERSION: &str = "iop-sdk-rust-20231210";

const P_APPKEY: &str = "app_key";
const P_API: &str = "method";
#[allow(dead_code)]
const P_METHOD: &str = "method";
const P_SESSION: &str = "session";
#[allow(dead_code)]
const P_ACCESS_TOKEN: &str = "access_token";
const P_VERSION: &str = "v";
const P_FORMAT: &str = "format";
const P_TIMESTAMP: &str = "timestamp";
const P_SIGN: &str = "sign";
const P_SIGN_METHOD: &str = "sign_method";
const P_PARTNER_ID: &str = "partner_id";
#[allow(dead_code)]
const P_DEBUG: &str = "debug";
#[allow(dead_code)]
const P_SIMPLIFY: &str = "simplify";

#[allow(dead_code)]
const P_CODE: &str = "code";
#[allow(dead_code)]
const P_TYPE: &str = "type";
#[allow(dead_code)]
const P_MESSAGE: &str = "message";
#[allow(dead_code)]
const P_REQUEST_ID: &str = "request_id";

const N_REST: &str = "/rest";
const N_SYNC: &str = "/sync";

const P_API_GATEWAY_URL_BUSINESS:&str = "api-sg.aliexpress.com";
const P_API_GATEWAY_URL_SYSTEM:&str = "api-sg.aliexpress.com";
#[allow(dead_code)]
const P_API_AUTHORIZATION_URL:&str = "https://auth.taobao.tw/rest";

#[allow(dead_code)]
const GENERATE_SECURITY_TOKEN_URL: &str = "/auth/token/security/create";
#[allow(dead_code)]
const GENERATE_TOKEN_URL: &str = "/auth/token/create";
#[allow(dead_code)]
const REFRESH_SECURITY_TOKEN_URL: &str = "/auth/token/security/refresh";
#[allow(dead_code)]
const REFRESH_TOKEN_URL: &str = "/auth/token/refresh";

#[allow(dead_code)]
const P_LOG_LEVEL_DEBUG: &str = "DEBUG";
#[allow(dead_code)]
const P_LOG_LEVEL_INFO: &str = "INFO";
#[allow(dead_code)]
const P_LOG_LEVEL_ERROR: &str = "ERROR";

pub type RequestParameters = HashMap<String, String>;

#[allow(dead_code)]
#[derive(Debug)]
pub enum IopError{
    SourceValueNotAllowedError,
    RequestError(reqwest::Error),
}

impl std::fmt::Display for IopError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::SourceValueNotAllowedError => write!(f, "Source value not allowed!"),
            Self::RequestError(error) =>  write!(f, "Request Error: {}", error.to_string()),
        }
    }
}

impl std::error::Error for IopError {}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[allow(dead_code)]
#[derive(PartialEq)]
pub enum SignMethod {
    Md5,
    HmacMd5,
    HmacSha256,
}

impl Display for SignMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use SignMethod::*;
        match &self {
            Md5 => "md5",
            HmacMd5 => "md5",
            HmacSha256 => "sha256",
        }
        .fmt(f)
    }
}

#[allow(dead_code)]
pub enum HttpMethod {
    Post,
    Get,
    Update,
    Put,
}

impl Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use HttpMethod::*;
        match &self {
            Post => "post",
            Get => "get",
            Update => "update",
            Put => "put",
        }
        .fmt(f)
    }
}

#[allow(dead_code)]
pub enum DevicesIds {
    Adid,   //adid: Android
    Afai,   //afai: Amazon
    Idfa,   //idfa: Apple phones (iOS)
    Lgudid, //lgudid: LG
    Msai,   //msai: Xbox
    Rida,   //rida: Roku
    Tifa,   //tifa: Samsung
    TvOS,   //tvOS: AppleTV (tvOS)
    Vaid,   //vaid: VIDAA OS
    Vida,   //vida: Vizio
}

impl Display for DevicesIds {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use DevicesIds::*;
        match &self {
            Adid => "adid",     // Android
            Afai => "afai",     // Amazon
            Idfa => "idfa",     // Apple phones (iOS)
            Lgudid => "lgudid", // LG
            Msai => "msai",     // Xbox
            Rida => "rida",     // Roku
            Tifa => "tifa",     // Samsung
            TvOS => "tvOS",     // AppleTV (tvOS)
            Vaid => "vaid",     // VIDAA OS
            Vida => "vida",     // Vizio
        }
        .fmt(f)
    }
}

#[derive(PartialEq)]
enum RequestType {
    System,
    Business,
}

#[allow(dead_code)]
pub enum ApiName {
    // System
    GenerateSecurityToken, // /auth/token/security/create
    GenerateToken,         // /auth/token/create
    RefreshSecurityToken,  // /auth/token/security/refresh
    RefreshToken,          // /auth/token/refresh

    // AE-Affiliate
    GenerateAffiliateLinks,   // aliexpress.affiliate.link.generate
    GetCategory,              // aliexpress.affiliate.category.get
    GetFeaturedPromoInfo,     // aliexpress.affiliate.featuredpromo.get
    GetFeaturedPromoProducts, // aliexpress.affiliate.featuredpromo.products.get
    GetHotProductDownload,    // aliexpress.affiliate.hotproduct.download
    GetHotProducts,           // aliexpress.affiliate.hotproduct.query
    GetOrderInfo,             // aliexpress.affiliate.order.get
    GetOrderList,             // aliexpress.affiliate.order.list
    GetOrderListByIndex,      // aliexpress.affiliate.order.listbyindex
    GetProductDetailInfo,     // aliexpress.affiliate.productdetail.get
    GetProducts,              // aliexpress.affiliate.product.query
    SmartMatchProducts,       // aliexpress.affiliate.product.smartmatch

    //AE-Logistics
    DbsdeclareShip,             //aliexpress.asf.dbs.declareship
    ModifyDbsDeclareShip,       //aliexpress.asf.dbs.declare.ship.modify
    OnlinePackagingAndShipment, //aliexpress.asf.shipment.pack
    OrderShippingServiceQuery,  //aliexpress.asf.order.shipping.service.get
    PackageAvailableShippingServiceQuery, //aliexpress.asf.package.shipping.service.get
    PlatformLogisticsOrderDocumentQuery,  //aliexpress.asf.platform.logistics.document.query
    PlatformLogisticsReadyToShip,         //aliexpress.asf.platform.logistics.rts
    PlatformLogisticsRepack,              //aliexpress.asf.platform.logistics.repack
    SellerAddressQuery,                  //aliexpress.asf.seller.address.get

    //AE-Dropshipper
    NewFreightQueryAPI,  //aliexpress.ds.freight.query
    APIForFetchAECategorysIDAndCategoryName, //aliexpress.ds.category.get
    APIForPlaceOrder, //aliexpress.trade.buy.placeorder
    FetchFeednameForDSBusiness, //aliexpress.ds.feedname.get
    FetchItemListByFeedname,  //aliexpress.ds.recommend.feed.get
    FreightCalculation,  //aliexpress.logistics.buyer.freight.get
    FreightCalculationInterfaceProvidedForBuyers, //aliexpress.logistics.buyer.freight.calculate
    QueryLogisticsTrackingInformation,  //aliexpress.logistics.ds.trackinginfo.query
    AddDsInfo, //aliexpress.ds.add.info aliexpress.ds.add.info 
    AeDropshiperImageSearch, //aliexpress.ds.image.search
    BuyerQueryOrderDetails, //aliexpress.trade.ds.order.get
    DsOrderQueryByIndex, //aliexpress.ds.commissionorder.listbyindex
    DsOrderSubmit, //aliexpress.ds.member.orderdata.submit
    GetProductsSpecialInfoLikeCertification, //aliexpress.ds.product.specialinfo.get
    ProductInfoQueryForDs, //aliexpress.ds.product.get

    //AE-Image
    PagedQueryImagesInPhotobank,  // aliexpress.photobank.redefining.listimagepagination
    UploadImagesToPhotoBank,  // aliexpress.photobank.redefining.uploadimageforsdk
    DeleteUnreferencedImages, // aliexpress.photobank.redefining.delunusephoto

    //AE-Category&Attributes
    AEGetPropValueFeature, // aliexpress.category.redefining.getPropValueFeature
    GetCategorySuggestion, // /v2.0/categories/suggestion
    GetChildAttributesOfAPostCategorysId, //aliexpress.category.redefining.getchildattributesresultbypostcateidandpath
    QueryTheSkuAttributeInformationBelongedToASpecificCategory, //aliexpress.solution.sku.attribute.query
    APIForSellerToQueryTheCategoryTree, // aliexpress.solution.seller.category.tree.query

    //AE-Freight (Shipment)
    ListAllFreightTemplates, //aliexpress.freight.redefining.listfreighttemplate

    //AE-Order & Transaction
    GetOrderReceiptInfo, //aliexpress.solution.order.receiptinfo.get 
    GetOrderListFromAliExpress, //aliexpress.solution.order.get
    TradeOrderDetailsQuery, //aliexpress.trade.new.redefining.findorderbyid
    FulfillOrder, //aliexpress.solution.order.fulfill

    //AE-Product Management
    BatchProductPriceUpdate,  //aliexpress.solution.batch.product.price.update
    CreateProductGroup,  //aliexpress.postproduct.redefining.createproductgroup
    EditProductAPI,  //aliexpress.solution.product.edit
    GetSingleProductInfo,   //aliexpress.solution.product.info.get
    GetProductList,  //aliexpress.solution.product.list.get
    GetTheCurrentMembersProductGrouping,   //aliexpress.product.productgroups.get
    GoodsOffTheShelfInterface,  //aliexpress.postproduct.redefining.offlineaeproduct
    InvalidateSpecificFeedsBasedOnJobIds,  //aliexpress.solution.feed.invalidate
    OnlineAEProduc,  //aliexpress.postproduct.redefining.onlineaeproduct
    ProductPostingAPI,  //aliexpress.solution.product.post
    SetProductGroup,  //aliexpress.postproduct.redefining.setgroups
    UploadProductBasedOnJsonSchemaInstance,  //aliexpress.solution.schema.product.instance.post
    ApiIsUsedToDeleteOnlineProductsExceptInTheDraftBox, //aliexpress.solution.batch.product.delete
    APIForOverseaSellersTOBatchProductInventoryUpdate,  //aliexpress.solution.batch.product.inventory.update
    APIToQueryTheFeedListBelongedToASeller,  //aliexpress.solution.feed.list.get
    APIForQueryTheExecutionResultOfFeed,  //aliexpress.solution.feed.query
    APIForMerchantsToSubmitFeedData,  //aliexpress.solution.feed.submit
    APIForLogisticsISVsToObtainTheHscodeBasedOnTheCategoryOfTheProduct,  //aliexpress.solution.hscode.query
    APIForOverseaSellersToObtainTheNormalInformation,   //aliexpress.solution.merchant.profile.get
    SchemaInterfaceForProductFullUpdate,  //aliexpress.solution.schema.product.full.update
    GetProductSchema,  //aliexpress.solution.product.schema.get
}

impl ApiName {
    fn get_request_type(&self) -> RequestType {
        use ApiName::*;
        match self {
            GenerateSecurityToken | GenerateToken | RefreshSecurityToken | RefreshToken => {
                RequestType::System
            }
            _ => RequestType::Business,
        }
    }
}

impl Display for ApiName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ApiName::*;
        match &self {
            // System
            GenerateSecurityToken => "/auth/token/security/create",
            GenerateToken => "/auth/token/create",
            RefreshSecurityToken => "/auth/token/security/refresh",
            RefreshToken => "/auth/token/refresh",

            // AE-Affiliate
            GenerateAffiliateLinks => "aliexpress.affiliate.link.generate",
            GetCategory => "aliexpress.affiliate.category.get",
            GetFeaturedPromoInfo => "aliexpress.affiliate.featuredpromo.get",
            GetFeaturedPromoProducts => "aliexpress.affiliate.featuredpromo.products.get",
            GetHotProductDownload => "aliexpress.affiliate.hotproduct.download",
            GetHotProducts => "aliexpress.affiliate.hotproduct.query",
            GetOrderInfo => "aliexpress.affiliate.order.get",
            GetOrderList => "aliexpress.affiliate.order.list",
            GetOrderListByIndex => "aliexpress.affiliate.order.listbyindex",
            GetProductDetailInfo => "aliexpress.affiliate.productdetail.get",
            GetProducts => "aliexpress.affiliate.product.query",
            SmartMatchProducts => "aliexpress.affiliate.product.smartmatch",

            //AE-Logistics
            DbsdeclareShip => "aliexpress.asf.dbs.declareship",
            ModifyDbsDeclareShip => "aliexpress.asf.dbs.declare.ship.modify",
            OnlinePackagingAndShipment => "aliexpress.asf.shipment.pack",
            OrderShippingServiceQuery => "aliexpress.asf.order.shipping.service.get",
            PackageAvailableShippingServiceQuery => "aliexpress.asf.package.shipping.service.get",
            PlatformLogisticsOrderDocumentQuery => "aliexpress.asf.platform.logistics.document.query",
            PlatformLogisticsReadyToShip => "aliexpress.asf.platform.logistics.rts",
            PlatformLogisticsRepack => "aliexpress.asf.platform.logistics.repack",
            SellerAddressQuery => "aliexpress.asf.seller.address.get",

            //AE-Dropshipper
            NewFreightQueryAPI => "aliexpress.ds.freight.query",
            APIForFetchAECategorysIDAndCategoryName => "aliexpress.ds.category.get",
            APIForPlaceOrder => "aliexpress.trade.buy.placeorder",
            FetchFeednameForDSBusiness => "aliexpress.ds.feedname.get",
            FetchItemListByFeedname => "aliexpress.ds.recommend.feed.get",
            FreightCalculation => "aliexpress.logistics.buyer.freight.get",
            FreightCalculationInterfaceProvidedForBuyers => "aliexpress.logistics.buyer.freight.calculate",
            QueryLogisticsTrackingInformation => "aliexpress.logistics.ds.trackinginfo.query",
            AddDsInfo => "aliexpress.ds.add.info aliexpress.ds.add.info",
            AeDropshiperImageSearch => "aliexpress.ds.image.search",
            BuyerQueryOrderDetails => "aliexpress.trade.ds.order.get",
            DsOrderQueryByIndex => "aliexpress.ds.commissionorder.listbyindex",
            DsOrderSubmit => "aliexpress.ds.member.orderdata.submit",
            GetProductsSpecialInfoLikeCertification => "aliexpress.ds.product.specialinfo.get",
            ProductInfoQueryForDs => "aliexpress.ds.product.get",

            //AE-Image
            PagedQueryImagesInPhotobank => "aliexpress.photobank.redefining.listimagepagination",
            UploadImagesToPhotoBank => "aliexpress.photobank.redefining.uploadimageforsdk",
            DeleteUnreferencedImages => "aliexpress.photobank.redefining.delunusephoto",

            //AE-Category&Attributes
            AEGetPropValueFeature => "aliexpress.category.redefining.getPropValueFeature",
            GetCategorySuggestion => "/v2.0/categories/suggestion",
            GetChildAttributesOfAPostCategorysId => "aliexpress.category.redefining.getchildattributesresultbypostcateidandpath",
            QueryTheSkuAttributeInformationBelongedToASpecificCategory => "aliexpress.solution.sku.attribute.query",
            APIForSellerToQueryTheCategoryTree => "aliexpress.solution.seller.category.tree.query",

            //AE-Freight (Shipment)
            ListAllFreightTemplates => "aliexpress.freight.redefining.listfreighttemplate",

            //AE-Order & Transaction
            GetOrderReceiptInfo => "aliexpress.solution.order.receiptinfo.get",
            GetOrderListFromAliExpress => "aliexpress.solution.order.get",
            TradeOrderDetailsQuery => "aliexpress.trade.new.redefining.findorderbyid",
            FulfillOrder => "aliexpress.solution.order.fulfill",

            //AE-Product Management
            BatchProductPriceUpdate => "aliexpress.solution.batch.product.price.update",
            CreateProductGroup => "aliexpress.postproduct.redefining.createproductgroup",
            EditProductAPI => "aliexpress.solution.product.edit",
            GetSingleProductInfo => "aliexpress.solution.product.info.get",
            GetProductList => "aliexpress.solution.product.list.get",
            GetTheCurrentMembersProductGrouping => "aliexpress.product.productgroups.get",
            GoodsOffTheShelfInterface => "aliexpress.postproduct.redefining.offlineaeproduct",
            InvalidateSpecificFeedsBasedOnJobIds => "aliexpress.solution.feed.invalidate",
            OnlineAEProduc => "aliexpress.postproduct.redefining.onlineaeproduct",
            ProductPostingAPI => "aliexpress.solution.product.post",
            SetProductGroup => "aliexpress.postproduct.redefining.setgroups",
            UploadProductBasedOnJsonSchemaInstance => "aliexpress.solution.schema.product.instance.post",
            ApiIsUsedToDeleteOnlineProductsExceptInTheDraftBox => "aliexpress.solution.batch.product.delete",
            APIForOverseaSellersTOBatchProductInventoryUpdate => "aliexpress.solution.batch.product.inventory.update",
            APIToQueryTheFeedListBelongedToASeller => "aliexpress.solution.feed.list.get",
            APIForQueryTheExecutionResultOfFeed => "aliexpress.solution.feed.query",
            APIForMerchantsToSubmitFeedData => "aliexpress.solution.feed.submit",
            APIForLogisticsISVsToObtainTheHscodeBasedOnTheCategoryOfTheProduct => "aliexpress.solution.hscode.query",
            APIForOverseaSellersToObtainTheNormalInformation => "aliexpress.solution.merchant.profile.get",
            SchemaInterfaceForProductFullUpdate => "aliexpress.solution.schema.product.full.update",
            GetProductSchema => "aliexpress.solution.product.schema.get",
        }
        .fmt(f)
    }
}

#[allow(dead_code)]
pub struct Iop {
    app_key: String,
    secret: String,
    business_domain: String,
    system_domain: String,
    port: u32,
    httpmethod: HttpMethod,
    api_name: String,
}

#[allow(dead_code)]
impl Iop {
    pub fn new(app_key: &str, secret: &str) -> Self {

        Iop {
            app_key: app_key.to_string(),
            secret: secret.to_string(),
            business_domain: String::from(P_API_GATEWAY_URL_BUSINESS),
            system_domain: String::from(P_API_GATEWAY_URL_SYSTEM),
            port: 443,
            httpmethod: HttpMethod::Get,
            api_name: ApiName::GetFeaturedPromoInfo.to_string(),
        }
    }

    pub fn set_app_info(mut self, app_key: &str, secret: &str) {
        self.app_key = app_key.to_string();
        self.secret = secret.to_string();
    }

    pub fn set_business_domain(mut self, business_domain: &str) {
        self.business_domain = business_domain.to_string();
    }

    pub fn set_system_domain(mut self, system_domain: &str) {
        self.system_domain = system_domain.to_string();
    }

    pub fn set_port(mut self, port: u32) {
        self.port = port;
    }

    pub fn set_httpmethod(mut self, httpmethod: HttpMethod) {
        self.httpmethod = httpmethod;
    }

    pub fn set_api_name(&mut self, api_name: &str) {
        self.api_name = api_name.to_string();
    }

    pub fn get_api_name(&self) -> &str {
        &self.api_name
    }

    pub async fn generate_security_token(
        &self,
        code: String,
        uuid: String,
    ) -> Result<reqwest::Response> {
        let mut request_parameters: RequestParameters = HashMap::new();

        request_parameters.insert("code".to_string(), code);
        request_parameters.insert("uuid".to_string(), uuid);

        let response = self
            .request(ApiName::GenerateSecurityToken, Some(request_parameters))
            .await;

        response
    }

    pub async fn generate_token(&self, code: String, uuid: String) -> Result<reqwest::Response> {
        let mut request_parameters: RequestParameters = HashMap::new();

        request_parameters.insert("code".to_string(), code);
        request_parameters.insert("uuid".to_string(), uuid);

        let response = self
            .request(ApiName::GenerateToken, Some(request_parameters))
            .await;

        response
    }

    pub async fn refresh_security_token(&self, refresh_token: String) -> Result<reqwest::Response> {
        let mut request_parameters: RequestParameters = HashMap::new();
        request_parameters.insert("refresh_token".to_string(), refresh_token);
        let response = self
            .request(ApiName::RefreshSecurityToken, Some(request_parameters))
            .await;
        response
    }

    pub async fn refresh_token(&self, refresh_token: String) -> Result<reqwest::Response> {
        let mut request_parameters: RequestParameters = HashMap::new();
        request_parameters.insert("refresh_token".to_string(), refresh_token);
        let response = self
            .request(ApiName::RefreshToken, Some(request_parameters))
            .await;
        response
    }

    pub async fn request(
        &self,
        api: ApiName,
        request_parameters: Option<RequestParameters>,
    ) -> Result<reqwest::Response> {

        let mut base_url = 'base_url: {
            let protocol = 'protocol:{
                if self.port == 443 {
                    break 'protocol "https";
                } 
                break 'protocol "http";
            };
            if api.get_request_type() == RequestType::System {

                let mut url = reqwest::Url::parse(
                    format!("{}://{}",protocol, self.system_domain.as_str()).as_str()
                ).unwrap();
                
                url.set_path(N_REST);
                url.set_path(api.to_string().as_str());

                break 'base_url url;
            }

            let mut url = reqwest::Url::parse(
                format!("{}://{}",protocol, self.business_domain.as_str()).as_str()
            ).unwrap();
            
            url.set_path(N_SYNC);

            break 'base_url url;
        }; 

        let parameters = self.make_parameters(api, None, request_parameters);

        if parameters.is_err(){
            return Err(parameters.err().unwrap())
        }

        let request_url = self.add_params_to_request_url(&mut base_url, parameters.unwrap());

        if request_url.is_err(){
            return Err(request_url.err().unwrap())
        }

        //println!("{:?}", &request_url.unwrap());

        // TODO: 1. Fix Post method
        // TODO: 2. Add more methods
        match self.httpmethod {
            HttpMethod::Post => Self::make_post_request(request_url.unwrap(), "").await,
            _ => Self::make_get_request(request_url.unwrap()).await,
        }
    }

    fn parse_url_paramater(&self, key: &str, value: &str) -> Result<String>{
        let url_query_keys = vec!["source_values", "image_url", "shop_url"];
        if url_query_keys.contains(&key){
            return match reqwest::Url::parse(value) {
                Ok(url) => {
                    return Ok(url.as_str().to_string())
                },
                Err(_err) => Err(
                    Box::new(IopError::SourceValueNotAllowedError)
                )
            }
            
        }
        Ok(value.to_string())
    }

    fn add_params_to_request_url(
        &self, 
        base_url: &mut reqwest::Url, 
        parameters: RequestParameters
    ) -> Result<reqwest::Url>  
    {

        for (key, value) in parameters.iter().sorted() {
            if !value.is_empty() {
                let val = self.parse_url_paramater(key, value);

                if val.is_err(){
                    return Err(val.err().unwrap())
                }

                base_url.query_pairs_mut().append_pair(key, &val.unwrap());
            }
        }

        Ok(base_url.to_owned())
    }

    fn make_parameters(
        &self,
        api: ApiName,
        authrize: Option<String>,
        request_parameters: Option<RequestParameters>,
    ) -> Result<RequestParameters> {
        let dt = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let timestamp = dt.as_nanos() / 1000000;

        let mut sys_parameters: HashMap<String, String> = HashMap::new();

        sys_parameters.insert(P_FORMAT.to_string(), String::from("json"));
        sys_parameters.insert(P_APPKEY.to_string(), (&self.app_key).to_string());
        sys_parameters.insert(P_SIGN_METHOD.to_string(), String::from("md5"));
        sys_parameters.insert(P_VERSION.to_string(), String::from("2.0"));
        sys_parameters.insert(P_TIMESTAMP.to_string(), timestamp.to_string());
        sys_parameters.insert(
            P_PARTNER_ID.to_string(),
            String::from(SYSTEM_GENERATE_VERSION),
        );

        if api.get_request_type() == RequestType::Business {
            sys_parameters.insert(P_API.to_string(), api.to_string());
        }

        if let Some(aut) = authrize {
            sys_parameters.insert(P_SESSION.to_string(), aut);
        }

        if let Some(req_parameters) = request_parameters {
            //sys_parameters.extend(req_parameters.into_iter());
            for (key, value) in req_parameters.iter().sorted() {
                if !value.is_empty() {
                    let val = self.parse_url_paramater(key, value);
                    if val.is_err(){
                        return Err(val.err().unwrap())
                    }
                    sys_parameters.insert(key.to_string(), val.unwrap());
                }
            }
        }

        let sign = Self::sign(self.secret.as_str(), sys_parameters.clone(), "md5");

        sys_parameters.insert(P_SIGN.to_string(), sign);

        Ok(sys_parameters)
    }

    async fn make_get_request(url: reqwest::Url) -> Result<reqwest::Response> {
        let timeout = Duration::new(10, 0);
        let client = ClientBuilder::new().timeout(timeout).build();

        if client.is_err(){
            return Err(
                Box::new(IopError::RequestError(client.err().unwrap()))
            )
        }

        let response = client.unwrap()
            .get(url)
            .header(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/114.0.5735.99 Mobile/15E148 Safari/604.1"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded;charset=UTF-8")
            .header(CACHE_CONTROL, "no-cache")
            .header(CONNECTION, "Keep-Alive")
            .send()
            .await;

        if response.is_err(){
            return Err(
                Box::new(IopError::RequestError(response.err().unwrap()))
            )
        }

        Ok(response.unwrap())
    }

    async fn make_post_request(url: reqwest::Url, body: &str) -> Result<reqwest::Response> {
        let timeout = Duration::new(10, 0);
        let client = ClientBuilder::new().timeout(timeout).build();

        if client.is_err(){
            return Err(Box::new(IopError::RequestError(client.err().unwrap())))
        }

        let response = client.unwrap()
            .post(url)
            .header(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/114.0.5735.99 Mobile/15E148 Safari/604.1"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded;charset=UTF-8")
            .header(CACHE_CONTROL, "no-cache")
            .header(CONNECTION, "Keep-Alive")
            .body(body.to_string()) // TODO: repaire this
            .send()
            .await;

        if response.is_err(){
            return Err(
                Box::new(IopError::RequestError(response.err().unwrap()))
            )
        }

        Ok(response.unwrap())
    }

    pub fn sign(secret: &str, params: RequestParameters, sign_method: &str) -> String {
        //Step 1: Check whether parameters have been sorted.
        // let keys:Vec<String> = params.keys();
        // keys.sort();

        //Step 2: Splice all sorted parameter names and values together.
        let mut query = String::new();
        if SIGN_METHOD_MD5 == sign_method {
            query.push_str(secret);
        }

        for (key, value) in params.iter().sorted() {
            if !key.is_empty() && !value.is_empty() {
                query.push_str(key.as_str());
                query.push_str(value.as_str());
            }
        }

        //Step 3: Use the MD5 or HMAC_MD5 algorithm to encrypt the spliced character string.
        let bytes: Vec<u8> = 'bytes: {
            if SIGN_METHOD_HMAC == sign_method {
               break 'bytes Self::encrypt_hmac(query.as_str(), secret); 
            }
            query.push_str(secret);
            break 'bytes Self::encrypt_md5(query.as_str()); 
        }; 

        //Step 4: Convert binary characters into capitalized hexadecimal characters. (A correct signature must be a character string consisting of 32 capitalized hexadecimal characters. This step is performed as required.)
        let hex = Self::byte2hex(bytes);

        hex.to_uppercase()
    }

    //TODO: switch between h265 and md5
    fn encrypt_hmac(data: &str, secret: &str) -> Vec<u8> {
        let mut mac =
            HmacMd5::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(data.as_bytes());
        let result = mac.finalize();

        let bytes = result.into_bytes();

        bytes[..].to_vec()
    }

    fn encrypt_md5(data: &str) -> Vec<u8> {
        let mut hasher = Md5::new();

        // process input message
        hasher.update(data.as_bytes());
        let result = hasher.finalize();
        result[..].to_vec()
    }

    fn byte2hex(bytes: Vec<u8>) -> String {
        let hex: String = bytes
            .iter()
            .map(|b| format!("{:02x}", b).to_string())
            .collect::<Vec<String>>()
            .join("");
        hex
    }
}
