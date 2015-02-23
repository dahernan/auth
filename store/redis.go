package store

// func (r *RedisRepository) Signin(email, pass string) (string, error) {
// 	log.Println("INFO: New user Signin", email)

// 	_, err := r.UserByEmail(email)
// 	if err == nil {
// 		log.Println("INFO: Duplicated Email: ", email)
// 		// user is already in the system
// 		return "", ErrEmailDuplication
// 	}

// 	id, err := r.client.Incr(usersIdKey)
// 	if err != nil {
// 		return "", err
// 	}
// 	userId := strconv.FormatInt(id, 10)

// 	salt := GenerateRandomKey(32)
// 	hpass, err := HashPassword(pass, salt)

// 	if err != nil {
// 		return "", err
// 	}

// 	data := map[string]string{
// 		"Email":    email,
// 		"UserId":   userId,
// 		"Password": string(hpass),
// 		"Salt":     string(salt),
// 	}

// 	err = r.client.HMSet(userKey+userId, data)
// 	if err != nil {
// 		return "", err
// 	}

// 	err = r.SetEmail(email, userId)
// 	if err != nil {
// 		return "", err
// 	}

// 	return userId, nil

// }

// func (r *RedisRepository) Login(email, pass string) (string, error) {
// 	id, err := r.UserByEmail(email)
// 	if err != nil {
// 		return "", err
// 	}
// 	userId := string(id)
// 	if userId == "" {
// 		return "", ErrUserNotFound
// 	}

// 	data, err := r.client.HMGet(userKey+userId, "Password", "Salt")
// 	if err != nil {
// 		return "", err
// 	}
// 	if string(data[0]) == "" {
// 		return "", ErrUserNotFound
// 	}
// 	passStored := data[0]
// 	salt := data[1]

// 	hpass, err := HashPassword(pass, salt)
// 	if err != nil {
// 		return "", err
// 	}
// 	passOk := SecureCompare(hpass, passStored)
// 	if !passOk {
// 		return "", ErrWrongPassword
// 	}

// 	r.client.HSet(userKey+userId, "Lastlogin", strconv.FormatInt(time.Now().Unix(), 10))
// 	log.Println("INFO: User Login", userId, email)

// 	return userId, nil
// }
