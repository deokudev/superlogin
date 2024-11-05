"use strict";
var BPromise = require("bluebird");
var util = require("../util");

module.exports = function (couchAuthDB) {
  this.storeKey = function (username, key, password, expires, roles) {
    if (roles instanceof Array) {
      roles = roles.slice(); // Clone roles to not overwrite original
    } else {
      roles = [];
    }
    roles.unshift("user:" + username);
    var newKey = {
      _id: "org.couchdb.user:" + key,
      type: "user",
      name: key,
      user_id: username,
      password: password, // 비밀번호 확인
      expires: expires, // 만료 시간 확인
      roles: roles,
    };

    // 전송할 문서 로그
    console.log("NewKey to be sent:", JSON.stringify(newKey));

    return couchAuthDB
      .put(newKey)
      .then(function () {
        newKey._id = key; // ID 수정
        return BPromise.resolve(newKey);
      })
      .catch(function (error) {
        console.error("Error putting newKey:", error);
        throw error; // 에러 로그 후 재던짐
      });
  };

  this.removeKeys = function (keys) {
    keys = util.toArray(keys);
    var keylist = keys.map(function (key) {
      return "org.couchdb.user:" + key;
    });

    var toDelete = [];
    return couchAuthDB
      .allDocs({ keys: keylist })
      .then(function (keyDocs) {
        keyDocs.rows.forEach(function (row) {
          if (!row.error && !row.value.deleted) {
            var deletion = {
              _id: row.id,
              _rev: row.value.rev,
              _deleted: true,
            };
            toDelete.push(deletion);
          }
        });
        if (toDelete.length) {
          return couchAuthDB.bulkDocs(toDelete);
        } else {
          return BPromise.resolve(false);
        }
      })
      .catch(function (error) {
        console.error("Error removing keys:", error);
        throw error;
      });
  };

  this.initSecurity = function (db, adminRoles, memberRoles) {
    var changes = false;
    return db
      .get("_security")
      .then(function (secDoc) {
        if (!secDoc.admins) {
          secDoc.admins = { names: [], roles: [] };
        }

        if (!secDoc.admins.roles) {
          secDoc.admins.roles = [];
        }

        if (!secDoc.members) {
          secDoc.members = { names: [], roles: [] };
        }

        if (!secDoc.members.roles) {
          secDoc.admins.roles = [];
        }

        adminRoles.forEach(function (role) {
          if (!secDoc.admins.roles.includes(role)) {
            changes = true;
            secDoc.admins.roles.push(role);
          }
        });
        memberRoles.forEach(function (role) {
          if (!secDoc.members.roles.includes(role)) {
            changes = true;
            secDoc.members.roles.push(role);
          }
        });
        if (changes) {
          return putSecurityCouch(db, secDoc);
        } else {
          return BPromise.resolve(false);
        }
      })
      .catch(function (error) {
        console.error("Error initializing security:", error);
        throw error;
      });
  };

  this.authorizeKeys = function (user_id, db, keys) {
    var secDoc;
    if (typeof keys === "object" && !(keys instanceof Array)) {
      keys = Object.keys(keys);
    }
    keys = util.toArray(keys);

    return db
      .get("_security")
      .then(function (doc) {
        secDoc = doc;
        if (!secDoc.members) {
          secDoc.members = { names: [], roles: [] };
        }
        var changes = false;
        keys.forEach(function (key) {
          if (!secDoc.members.names.includes(key)) {
            secDoc.members.names.push(key);
            changes = true;
          }
        });
        if (changes) {
          return putSecurityCouch(db, secDoc);
        } else {
          return BPromise.resolve(false);
        }
      })
      .catch(function (error) {
        console.error("Error authorizing keys:", error);
        throw error;
      });
  };

  this.deauthorizeKeys = function (db, keys) {
    var secDoc;
    keys = util.toArray(keys);
    return db
      .get("_security")
      .then(function (doc) {
        secDoc = doc;
        if (!secDoc.members || !secDoc.members.names) {
          return BPromise.resolve(false);
        }
        var changes = false;
        keys.forEach(function (key) {
          var index = secDoc.members.names.indexOf(key);
          if (index > -1) {
            secDoc.members.names.splice(index, 1);
            changes = true;
          }
        });
        if (changes) {
          return putSecurityCouch(db, secDoc);
        } else {
          return BPromise.resolve(false);
        }
      })
      .catch(function (error) {
        console.error("Error deauthorizing keys:", error);
        throw error;
      });
  };

  function putSecurityCouch(db, doc) {
    return db.put("_security", doc).catch(function (error) {
      console.error("Error putting security doc:", error);
      throw error;
    });
  }

  return this;
};
