#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>
#import "sodium-jsi.h"
#import "sodium.h"

@interface RCTSodium : NSObject <RCTBridgeModule>

@property (nonatomic, assign) BOOL setBridgeOnMainQueue;

@end
