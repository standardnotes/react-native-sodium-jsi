#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import "RCTSodium.h"
#import "sodium-jsi.h"

@implementation RCTSodium

@synthesize bridge = _bridge;

NSString * const ESODIUM = @"ESODIUM";
NSString * const ERR_BAD_KEY = @"BAD_KEY";
NSString * const ERR_BAD_MAC = @"BAD_MAC";
NSString * const ERR_BAD_MSG = @"BAD_MSG";
NSString * const ERR_BAD_NONCE = @"BAD_NONCE";
NSString * const ERR_BAD_SEED = @"BAD_SEED";
NSString * const ERR_BAD_SIG = @"BAD_SIG";
NSString * const ERR_FAILURE = @"FAILURE";

RCT_EXPORT_MODULE();

+ (BOOL)requiresMainQueueSetup {
    return YES;
}

- (void)setBridge:(RCTBridge *)bridge {
    _bridge = bridge;
    _setBridgeOnMainQueue = RCTIsMainQueue();
    [self setup];
}

-(void)setup {
    RCTCxxBridge *cxxBridge = (RCTCxxBridge *)self.bridge;
    
    if (!cxxBridge.runtime) {
        // retry 10ms later - THIS IS A WACK WORKAROUND. wait for TurboModules to land.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.001 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            [self setup];
        });
        return;
    }
    
    install(*(facebook::jsi::Runtime *)cxxBridge.runtime);
}

- (void)invalidate {
    cleanup();
}


// *****************************************************************************
// * Sodium constants
// *****************************************************************************
- (NSDictionary *)constantsToExport
{
    return @{
        @"crypto_pwhash_SALTBYTES": @crypto_pwhash_SALTBYTES,
        @"crypto_pwhash_OPSLIMIT_MODERATE":@crypto_pwhash_OPSLIMIT_MODERATE,
        @"crypto_pwhash_OPSLIMIT_MIN":@crypto_pwhash_OPSLIMIT_MIN,
        @"crypto_pwhash_OPSLIMIT_MAX":@crypto_pwhash_OPSLIMIT_MAX,
        @"crypto_pwhash_MEMLIMIT_MODERATE":@crypto_pwhash_MEMLIMIT_MODERATE,
        @"crypto_pwhash_MEMLIMIT_MIN":@crypto_pwhash_MEMLIMIT_MIN,
        @"crypto_pwhash_MEMLIMIT_MAX":@crypto_pwhash_MEMLIMIT_MAX,
        @"crypto_pwhash_ALG_DEFAULT":@crypto_pwhash_ALG_DEFAULT,
        @"crypto_pwhash_ALG_ARGON2I13":@crypto_pwhash_ALG_ARGON2I13,
        @"crypto_pwhash_ALG_ARGON2ID13":@crypto_pwhash_ALG_ARGON2ID13,
        @"crypto_aead_xchacha20poly1305_IETF_ABYTES":@crypto_aead_chacha20poly1305_IETF_ABYTES,
        @"crypto_aead_xchacha20poly1305_IETF_KEYBYTES":@crypto_aead_xchacha20poly1305_IETF_KEYBYTES,
        @"crypto_aead_xchacha20poly1305_IETF_NPUBBYTES":@crypto_aead_xchacha20poly1305_IETF_NPUBBYTES,
        @"crypto_aead_xchacha20poly1305_IETF_NSECBYTES":@crypto_aead_xchacha20poly1305_IETF_NSECBYTES,
        @"base64_variant_ORIGINAL":@sodium_base64_VARIANT_ORIGINAL,
        @"base64_variant_VARIANT_ORIGINAL_NO_PADDING":@sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
        @"base64_variant_VARIANT_URLSAFE":@sodium_base64_VARIANT_URLSAFE,
        @"base64_variant_VARIANT_URLSAFE_NO_PADDING":@sodium_base64_VARIANT_URLSAFE_NO_PADDING,
    };
}

@end
