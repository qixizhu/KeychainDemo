//
//  ViewController.swift
//  KeychainHelper
//
//  Created by 韩企 on 2020/4/23.
//  Copyright © 2020 七夕猪. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        // IDFV
        UserKeychainHelper.shared.checkAndSaveIDFV()
        let IDFVString = UserKeychainHelper.shared.getIDFVString() ?? ""
        print("IDFV:" + IDFVString)
        
        // 用户名和密码
        let usernamePwd = Credentials(username: "username", password: "password")
        UserKeychainHelper.shared.save(credentials: usernamePwd)
        
        guard let credentials = UserKeychainHelper.shared.getCredentials() else {
            return
        }
        print("username: \(credentials.username), password: \(credentials.password)")
    }


}

