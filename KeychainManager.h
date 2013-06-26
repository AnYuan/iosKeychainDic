//
//  KeychainManager.h
//  ACBioUA_iOS_SB
//
//  Created by dongay on 13/01/28.
//  Copyright (c) 2013年 Neusoft. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface KeychainManager : NSObject
//初始化KeychainManager，并指定所要管理的Keychain item的名称
-(id)initWithKeychainIdentifier:(NSString *)identifier;

//将BRT证明书存入keychain保存
-(void)saveBRTCert:(id)BRTCert;
//读取BRT证明书
-(id)BRTCert;

//将端末ID存入keychain保存
-(void)saveMachineID:(id)machineID;
//读取端末ID
-(id)machineID;

//将私钥存入keychain保存
-(void)savePrivateKey:(id)privateKey;
//读取私钥
-(id)privateKey;

//将公钥存入keychain保存
-(void)savePublicKey:(id)publicKey;
//读取公钥
-(id)publicKey;

//将sessionId存入keychain保存
-(void)saveSessionID:(id)sessionID;
//读取sessionId
-(id)sessionId;

//将BRTIndex存入keychain保存
-(void)saveBRTIndex:(id)BRTIndex;
//读取BRTIndex
-(id)BRTIndex;


- (void)saveHashStringToKeychain:(NSString *)hashString;
- (NSString *)hashStringInKeychain;

//将KeychainManager管理的对应Keychain item清空
-(void)resetKeychain;

@end
