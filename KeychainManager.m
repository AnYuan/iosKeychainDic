//
//  KeychainManager.m
//  ACBioUA_iOS_SB
//
//  Created by dongay on 13/01/28.
//  Copyright (c) 2013年 Neusoft. All rights reserved.
//

#import "KeychainManager.h"
#import "KeychainItemWrapper.h"


#define BRT_CER        @"BRT_Cer"
#define MACHINE_ID     @"Machine_ID"
#define PRIVATE_KEY    @"Private_key"
#define PUBLIC_KEY     @"Public_key"
#define USER_ID        @"IDPUser_ID"
#define SESSION_ID     @"Session_ID"
#define BRT_INDEX      @"BRT_Index"
#define BRT_TARGET     @"BRT_Target"
#define HASH_STRING    @"Hash_String"

@interface KeychainManager()
@property (nonatomic,strong) KeychainItemWrapper *keychain; 
@end

@implementation KeychainManager
@synthesize keychain = _keychain;



-(id)initWithKeychainIdentifier:(NSString *)identifier
{
    return [[[KeychainManager alloc] init] keyChainWithIdentifier:identifier andAccessGroup:nil];
}

#pragma mark reset keychain item
-(void)resetKeychain
{
    [self.keychain cleanKeychainData];
}

#pragma mark init keychain manager and setup keychain

-(id)keyChainWithIdentifier:(NSString *)identifier andAccessGroup:(NSString *)accessGroup
{
    if (_keychain == nil) {
        _keychain = [[KeychainItemWrapper alloc] initWithIdentifier:identifier accessGroup:accessGroup];
    }
    return self;
}

#pragma mark IDPUserManager keychain item's setter and getter

-(void)saveMachineID:(id)machineID
{
    [self.keychain setACBioDicDataWithObject:machineID forKey:MACHINE_ID];
}
-(id)machineID
{
    return [[self.keychain ACBioDicData] objectForKey:MACHINE_ID];
}


-(id)sessionId
{
    return [[self.keychain ACBioDicData] objectForKey:SESSION_ID];
}
-(void)saveSessionID:(id)sessionID
{
    [self.keychain setACBioDicDataWithObject:sessionID forKey:SESSION_ID];
}

//
// 将UR社采集的数据的对应的hash值保存在keychain里.
//
// hashString:UR社采集的数据经处理后的对应的hash值.
//
- (void)saveHashStringToKeychain:(NSString *)hashString{
	[self.keychain setACBioDicDataWithObject:hashString forKey:HASH_STRING];
}

//
// 从keychain中取得先前保存的hashString.
//
// 返回值:keychain中的hashString.
//
- (NSString *)hashStringInKeychain{
	return [[self.keychain ACBioDicData] objectForKey:HASH_STRING];
}

#pragma mark BRTCManager keychain item's setter and getter

-(id)BRTIndex
{
    return [[self.keychain ACBioDicData] objectForKey:BRT_INDEX];
}
-(void)saveBRTIndex:(id)BRTIndex
{
    [self.keychain setACBioDicDataWithObject:BRTIndex forKey:BRT_INDEX];
}


-(void)saveBRTCert:(id)BRTCert
{
    [self.keychain setACBioDicDataWithObject:BRTCert forKey:BRT_CER];
}
-(id)BRTCert
{
    return [[self.keychain ACBioDicData] objectForKey:BRT_CER];
}

-(void)savePrivateKey:(id)privateKey
{
    [self.keychain setACBioDicDataWithObject:privateKey forKey:PRIVATE_KEY];
}
-(id)privateKey
{
    return [[self.keychain ACBioDicData] objectForKey:PRIVATE_KEY];
}

-(void)savePublicKey:(id)publicKey
{
    [self.keychain setACBioDicDataWithObject:publicKey forKey:PUBLIC_KEY];
}
-(id)publicKey
{
    return [[self.keychain ACBioDicData] objectForKey:PUBLIC_KEY];
}



@end
