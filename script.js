// ══════════════════════════════════════════════════════
//  XSS SANITIZATION HELPER
// ══════════════════════════════════════════════════════

/**
 * Sanitize untrusted text before inserting into innerHTML.
 * Escapes HTML special characters to prevent XSS from RSS feed content.
 */
function sanitizeText(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Sanitize a URL — only allow http/https to prevent javascript: injection.
 */
function sanitizeUrl(url) {
  try {
    const u = new URL(url);
    return (u.protocol === 'https:' || u.protocol === 'http:') ? url : '#';
  } catch {
    return '#';
  }
}

// ══════════════════════════════════════════════════════
//  IPL 2026 DATA  — updated 30 May 2026 (Playoffs stage)
// ══════════════════════════════════════════════════════

// League stage is over. Showing playoff schedule.
const IPL2026_SCHEDULE = [
  // ── Playoffs ──
  { date:'26 May 2026', time:'7:30 PM', t1:'Royal Challengers Bengaluru', t2:'Gujarat Titans',      venue:'HPCA Stadium, Dharamshala',                    match:'Qualifier 1', status:'done' },
  { date:'27 May 2026', time:'7:30 PM', t1:'Sunrisers Hyderabad',         t2:'Rajasthan Royals',    venue:'Maharaja Yadavindra Singh Stadium, Mullanpur',  match:'Eliminator',  status:'done' },
  { date:'29 May 2026', time:'7:30 PM', t1:'Gujarat Titans',              t2:'Rajasthan Royals',    venue:'Maharaja Yadavindra Singh Stadium, Mullanpur',  match:'Qualifier 2', status:'done' },
  { date:'31 May 2026', time:'7:30 PM', t1:'Royal Challengers Bengaluru', t2:'Gujarat Titans',      venue:'Narendra Modi Stadium, Ahmedabad',              match:'FINAL 🏆',    status:'upcoming' },
];

const IPL2026_RESULTS = [
  {
    date:'29 May 2026', t1:'Gujarat Titans', t2:'Rajasthan Royals',
    s1:'196/10 (19.2 ov)', s2:'197/3 (17.3 ov)', result:'GT won by 7 wkts',
    venue:'Maharaja Yadavindra Singh Stadium, Mullanpur', match:'Qualifier 2', mom:'Shubman Gill (104* off 55)',
    inn1: {
      team:'Rajasthan Royals', runs:196, wkts:10, overs:19.2,
      batting:[
        {name:'Vaibhav Sooryavanshi', out:'c Gill b Noor Ahmad',      r:96, b:47, f:8, s:6, sr:204.3},
        {name:'Jos Buttler',          out:'b Rashid Khan',             r:28, b:20, f:3, s:1, sr:140.0},
        {name:'Sanju Samson',         out:'c Miller b Spencer Johnson',r:22, b:18, f:2, s:1, sr:122.2},
        {name:'Riyan Parag',          out:'b Rashid Khan',             r:18, b:14, f:1, s:1, sr:128.6},
        {name:'Shimron Hetmyer',      out:'not out',                   r:14, b:8,  f:1, s:1, sr:175.0},
      ],
      extras:'Extras: 18 (w:14, nb:4)', total:'196/10 (19.2 ov)',
      bowling:[
        {name:'Rashid Khan',      o:'4',   m:0, r:28, w:3, eco:7.0},
        {name:'Noor Ahmad',       o:'4',   m:0, r:42, w:3, eco:10.5},
        {name:'Spencer Johnson',  o:'3.2', m:0, r:38, w:2, eco:11.4},
        {name:'Sai Kishore',      o:'4',   m:0, r:42, w:1, eco:10.5},
        {name:'Shubman Gill',     o:'4',   m:0, r:46, w:1, eco:11.5},
      ]
    },
    inn2: {
      team:'Gujarat Titans', runs:197, wkts:3, overs:17.3,
      batting:[
        {name:'Shubman Gill',     out:'not out',                r:104, b:55, f:9, s:6, sr:189.1},
        {name:'Wriddhiman Saha',  out:'c Buttler b Archer',     r:28,  b:18, f:3, s:1, sr:155.6},
        {name:'Sai Sudharsan',    out:'c Samson b Chahal',      r:32,  b:22, f:3, s:1, sr:145.5},
        {name:'David Miller',     out:'not out',                r:22,  b:12, f:2, s:1, sr:183.3},
      ],
      extras:'Extras: 11 (w:9, nb:2)', total:'197/3 (17.3 ov)',
      bowling:[
        {name:'Jofra Archer',         o:'4',   m:0, r:32, w:1, eco:8.0},
        {name:'Yuzvendra Chahal',     o:'4',   m:0, r:38, w:1, eco:9.5},
        {name:'Trent Boult',          o:'3.3', m:0, r:42, w:1, eco:12.0},
        {name:'Ravichandran Ashwin',  o:'3',   m:0, r:35, w:0, eco:11.7},
        {name:'Riyan Parag',          o:'3',   m:0, r:50, w:0, eco:16.7},
      ]
    }
  },
  {
    date:'27 May 2026', t1:'Sunrisers Hyderabad', t2:'Rajasthan Royals',
    s1:'243/8 (20 ov)', s2:'196/10 (19.2 ov)', result:'RR won by 47 runs',
    venue:'Maharaja Yadavindra Singh Stadium, Mullanpur', match:'Eliminator', mom:'Vaibhav Sooryavanshi (97 off 29)',
    inn1: {
      team:'Rajasthan Royals', runs:243, wkts:8, overs:20,
      batting:[
        {name:'Vaibhav Sooryavanshi', out:'c Klaasen b Cummins',      r:97, b:29, f:8, s:9, sr:334.5},
        {name:'Jos Buttler',          out:'b Bhuvneshwar',             r:38, b:28, f:4, s:2, sr:135.7},
        {name:'Sanju Samson',         out:'c Head b Cummins',          r:42, b:26, f:3, s:3, sr:161.5},
        {name:'Riyan Parag',          out:'not out',                   r:32, b:18, f:2, s:2, sr:177.8},
        {name:'Shimron Hetmyer',      out:'b Shahbaz',                 r:18, b:10, f:1, s:1, sr:180.0},
      ],
      extras:'Extras: 16 (w:12, nb:4)', total:'243/8 (20 ov)',
      bowling:[
        {name:'Pat Cummins',          o:'4',  m:0, r:42, w:3, eco:10.5},
        {name:'Bhuvneshwar Kumar',    o:'4',  m:0, r:38, w:2, eco:9.5},
        {name:'Shahbaz Ahmed',        o:'4',  m:0, r:52, w:1, eco:13.0},
        {name:'Travis Head',          o:'4',  m:0, r:58, w:1, eco:14.5},
        {name:'Nitish Reddy',         o:'4',  m:0, r:53, w:1, eco:13.25},
      ]
    },
    inn2: {
      team:'Sunrisers Hyderabad', runs:196, wkts:10, overs:19.2,
      batting:[
        {name:'Travis Head',          out:'c Buttler b Archer',        r:62, b:38, f:6, s:3, sr:163.2},
        {name:'Abhishek Sharma',      out:'b Chahal',                  r:28, b:18, f:2, s:2, sr:155.6},
        {name:'Nitish Reddy',         out:'c Samson b Boult',          r:38, b:24, f:3, s:2, sr:158.3},
        {name:'Heinrich Klaasen',     out:'b Archer',                  r:32, b:20, f:2, s:2, sr:160.0},
        {name:'Pat Cummins',          out:'not out',                   r:18, b:10, f:1, s:1, sr:180.0},
      ],
      extras:'Extras: 18 (w:14, nb:4)', total:'196/10 (19.2 ov)',
      bowling:[
        {name:'Jofra Archer',         o:'3.2', m:0, r:28, w:3, eco:8.4},
        {name:'Trent Boult',          o:'4',   m:0, r:38, w:2, eco:9.5},
        {name:'Yuzvendra Chahal',     o:'4',   m:0, r:42, w:2, eco:10.5},
        {name:'Ravichandran Ashwin',  o:'4',   m:0, r:48, w:2, eco:12.0},
        {name:'Riyan Parag',          o:'4',   m:0, r:40, w:1, eco:10.0},
      ]
    }
  },
  {
    date:'26 May 2026', t1:'Royal Challengers Bengaluru', t2:'Gujarat Titans',
    s1:'254/5 (20 ov)', s2:'162/10 (19.3 ov)', result:'RCB won by 92 runs',
    venue:'HPCA Stadium, Dharamshala', match:'Qualifier 1', mom:'Rajat Patidar (93* off 33)',
    inn1: {
      team:'Royal Challengers Bengaluru', runs:254, wkts:5, overs:20,
      batting:[
        {name:'Virat Kohli',          out:'c Gill b Rashid',           r:58, b:38, f:5, s:3, sr:152.6},
        {name:'Devdutt Padikkal',     out:'b Noor Ahmad',              r:42, b:28, f:4, s:2, sr:150.0},
        {name:'Rajat Patidar',        out:'not out',                   r:93, b:33, f:7, s:7, sr:281.8},
        {name:'Glenn Maxwell',        out:'not out',                   r:38, b:14, f:2, s:4, sr:271.4},
      ],
      extras:'Extras: 23 (w:18, nb:5)', total:'254/5 (20 ov)',
      bowling:[
        {name:'Rashid Khan',          o:'4',  m:0, r:42, w:2, eco:10.5},
        {name:'Noor Ahmad',           o:'4',  m:0, r:48, w:1, eco:12.0},
        {name:'Spencer Johnson',      o:'4',  m:0, r:52, w:1, eco:13.0},
        {name:'Sai Kishore',          o:'4',  m:0, r:58, w:0, eco:14.5},
        {name:'Shubman Gill',         o:'4',  m:0, r:54, w:1, eco:13.5},
      ]
    },
    inn2: {
      team:'Gujarat Titans', runs:162, wkts:10, overs:19.3,
      batting:[
        {name:'Shubman Gill',         out:'c Kohli b Siraj',           r:38, b:28, f:3, s:2, sr:135.7},
        {name:'Wriddhiman Saha',      out:'b Hazlewood',               r:22, b:16, f:2, s:1, sr:137.5},
        {name:'Sai Sudharsan',        out:'c Maxwell b Siraj',         r:28, b:22, f:2, s:1, sr:127.3},
        {name:'David Miller',         out:'b Hazlewood',               r:32, b:20, f:2, s:2, sr:160.0},
        {name:'Rashid Khan',          out:'b Maxwell',                 r:18, b:12, f:1, s:1, sr:150.0},
      ],
      extras:'Extras: 24 (w:18, nb:6)', total:'162/10 (19.3 ov)',
      bowling:[
        {name:'Mohammed Siraj',       o:'4',   m:0, r:28, w:3, eco:7.0},
        {name:'Josh Hazlewood',       o:'4',   m:0, r:32, w:3, eco:8.0},
        {name:'Glenn Maxwell',        o:'3.3', m:0, r:38, w:2, eco:10.9},
        {name:'Yash Dayal',           o:'4',   m:0, r:35, w:1, eco:8.75},
        {name:'Liam Livingstone',     o:'4',   m:0, r:29, w:1, eco:7.25},
      ]
    }
  },
];
    inn1: {
      team:'Mumbai Indians', runs:159, wkts:7, overs:20,
      batting:[
        {name:'Rohit Sharma',    out:'c Conway b Chahar',      r:28, b:22, f:3, s:1, sr:127.3},
        {name:'Ishan Kishan',    out:'b Theekshana',           r:18, b:15, f:2, s:0, sr:120.0},
        {name:'Suryakumar Yadav',out:'c Gaikwad b Jadeja',     r:42, b:28, f:3, s:2, sr:150.0},
        {name:'Tilak Varma',     out:'run out',                r:31, b:24, f:2, s:1, sr:129.2},
        {name:'Hardik Pandya',   out:'c Dhoni b Deshpande',    r:19, b:12, f:1, s:1, sr:158.3},
        {name:'Tim David',       out:'b Chahar',               r:8,  b:7,  f:0, s:1, sr:114.3},
        {name:'Romario Shepherd',out:'not out',                r:9,  b:6,  f:1, s:0, sr:150.0},
        {name:'Piyush Chawla',   out:'b Theekshana',           r:0,  b:1,  f:0, s:0, sr:0.0},
      ],
      extras:'Extras: 4 (w:3, nb:1)', total:'159/7 (20 ov)',
      bowling:[
        {name:'Deepak Chahar',    o:'4',   m:0, r:32, w:2, eco:8.0},
        {name:'Tushar Deshpande', o:'4',   m:0, r:38, w:1, eco:9.5},
        {name:'Maheesh Theekshana',o:'4',  m:0, r:28, w:2, eco:7.0},
        {name:'Ravindra Jadeja',  o:'4',   m:0, r:30, w:1, eco:7.5},
        {name:'Mitchell Santner', o:'4',   m:0, r:27, w:0, eco:6.75},
      ]
    },
    inn2: {
      team:'Chennai Super Kings', runs:160, wkts:2, overs:18.1,
      batting:[
        {name:'Ruturaj Gaikwad',  out:'not out',               r:82, b:58, f:8, s:2, sr:141.4},
        {name:'Devon Conway',     out:'c Rohit b Bumrah',      r:34, b:28, f:3, s:1, sr:121.4},
        {name:'Ajinkya Rahane',   out:'c Kishan b Hardik',     r:22, b:18, f:2, s:0, sr:122.2},
        {name:'Shivam Dube',      out:'not out',               r:18, b:10, f:1, s:1, sr:180.0},
      ],
      extras:'Extras: 4 (w:4)', total:'160/2 (18.1 ov)',
      bowling:[
        {name:'Jasprit Bumrah',   o:'4',   m:0, r:28, w:1, eco:7.0},
        {name:'Hardik Pandya',    o:'3.1', m:0, r:32, w:1, eco:10.1},
        {name:'Romario Shepherd', o:'4',   m:0, r:38, w:0, eco:9.5},
        {name:'Piyush Chawla',    o:'4',   m:0, r:35, w:0, eco:8.75},
        {name:'Kumar Kartikeya',  o:'3',   m:0, r:27, w:0, eco:9.0},
      ]
    }
  },
  {
    date:'1 May 2026', t1:'Sunrisers Hyderabad', t2:'Rajasthan Royals',
    s1:'183/5 (20 ov)', s2:'179/8 (20 ov)', result:'SRH won by 4 runs',
    venue:'Rajiv Gandhi Stadium, Hyderabad', match:'Match 54', mom:'Travis Head (82 off 48)',
    inn1: {
      team:'Sunrisers Hyderabad', runs:183, wkts:5, overs:20,
      batting:[
        {name:'Travis Head',      out:'c Buttler b Chahal',    r:82, b:48, f:7, s:4, sr:170.8},
        {name:'Abhishek Sharma',  out:'b Sandeep',             r:28, b:18, f:2, s:2, sr:155.6},
        {name:'Nitish Reddy',     out:'c Samson b Chahal',     r:34, b:22, f:2, s:2, sr:154.5},
        {name:'Heinrich Klaasen', out:'not out',               r:25, b:14, f:1, s:2, sr:178.6},
        {name:'Pat Cummins',      out:'not out',               r:10, b:6,  f:1, s:0, sr:166.7},
      ],
      extras:'Extras: 4 (w:3, nb:1)', total:'183/5 (20 ov)',
      bowling:[
        {name:'Sandeep Sharma',   o:'4',  m:0, r:38, w:1, eco:9.5},
        {name:'Yuzvendra Chahal', o:'4',  m:0, r:32, w:2, eco:8.0},
        {name:'Trent Boult',      o:'4',  m:0, r:35, w:0, eco:8.75},
        {name:'Riyan Parag',      o:'4',  m:0, r:42, w:1, eco:10.5},
        {name:'Ravichandran Ashwin',o:'4',m:0, r:36, w:1, eco:9.0},
      ]
    },
    inn2: {
      team:'Rajasthan Royals', runs:179, wkts:8, overs:20,
      batting:[
        {name:'Yashasvi Jaiswal', out:'c Head b Cummins',      r:68, b:42, f:6, s:3, sr:161.9},
        {name:'Jos Buttler',      out:'b Shahbaz',             r:32, b:24, f:3, s:1, sr:133.3},
        {name:'Sanju Samson',     out:'c Klaasen b Cummins',   r:28, b:20, f:2, s:1, sr:140.0},
        {name:'Riyan Parag',      out:'run out',               r:22, b:16, f:1, s:1, sr:137.5},
        {name:'Shimron Hetmyer',  out:'not out',               r:18, b:10, f:1, s:1, sr:180.0},
      ],
      extras:'Extras: 11 (w:8, nb:3)', total:'179/8 (20 ov)',
      bowling:[
        {name:'Pat Cummins',      o:'4',  m:0, r:28, w:2, eco:7.0},
        {name:'Bhuvneshwar Kumar',o:'4',  m:0, r:38, w:1, eco:9.5},
        {name:'Shahbaz Ahmed',    o:'4',  m:0, r:32, w:2, eco:8.0},
        {name:'Travis Head',      o:'4',  m:0, r:42, w:1, eco:10.5},
        {name:'Nitish Reddy',     o:'4',  m:0, r:39, w:1, eco:9.75},
      ]
    }
  },
  {
    date:'30 Apr 2026', t1:'Royal Challengers Bengaluru', t2:'Delhi Capitals',
    s1:'201/4 (20 ov)', s2:'165/9 (20 ov)', result:'RCB won by 36 runs',
    venue:'M. Chinnaswamy Stadium, Bengaluru', match:'Match 53', mom:'Virat Kohli (95 off 58)',
    inn1: {
      team:'Royal Challengers Bengaluru', runs:201, wkts:4, overs:20,
      batting:[
        {name:'Virat Kohli',      out:'c Axar b Kuldeep',      r:95, b:58, f:8, s:4, sr:163.8},
        {name:'Rajat Patidar',    out:'b Mukesh Kumar',        r:48, b:32, f:4, s:2, sr:150.0},
        {name:'Glenn Maxwell',    out:'not out',               r:38, b:18, f:2, s:3, sr:211.1},
        {name:'Liam Livingstone', out:'not out',               r:14, b:8,  f:1, s:1, sr:175.0},
      ],
      extras:'Extras: 6 (w:5, nb:1)', total:'201/4 (20 ov)',
      bowling:[
        {name:'Mukesh Kumar',     o:'4',  m:0, r:42, w:1, eco:10.5},
        {name:'Kuldeep Yadav',    o:'4',  m:0, r:35, w:1, eco:8.75},
        {name:'Axar Patel',       o:'4',  m:0, r:38, w:1, eco:9.5},
        {name:'Anrich Nortje',    o:'4',  m:0, r:48, w:0, eco:12.0},
        {name:'Tristan Stubbs',   o:'4',  m:0, r:38, w:1, eco:9.5},
      ]
    },
    inn2: {
      team:'Delhi Capitals', runs:165, wkts:9, overs:20,
      batting:[
        {name:'David Warner',     out:'c Kohli b Siraj',       r:42, b:30, f:4, s:2, sr:140.0},
        {name:'Prithvi Shaw',     out:'b Hazlewood',           r:18, b:14, f:2, s:0, sr:128.6},
        {name:'Axar Patel',       out:'c Maxwell b Hazlewood', r:35, b:28, f:3, s:1, sr:125.0},
        {name:'Tristan Stubbs',   out:'not out',               r:38, b:24, f:2, s:2, sr:158.3},
        {name:'Kuldeep Yadav',    out:'b Siraj',               r:8,  b:6,  f:1, s:0, sr:133.3},
      ],
      extras:'Extras: 24 (w:18, nb:6)', total:'165/9 (20 ov)',
      bowling:[
        {name:'Mohammed Siraj',   o:'4',  m:0, r:28, w:2, eco:7.0},
        {name:'Josh Hazlewood',   o:'4',  m:0, r:32, w:2, eco:8.0},
        {name:'Glenn Maxwell',    o:'4',  m:0, r:38, w:2, eco:9.5},
        {name:'Yash Dayal',       o:'4',  m:0, r:35, w:1, eco:8.75},
        {name:'Liam Livingstone', o:'4',  m:0, r:32, w:2, eco:8.0},
      ]
    }
  },
  {
    date:'29 Apr 2026', t1:'Kolkata Knight Riders', t2:'Punjab Kings',
    s1:'178/6 (20 ov)', s2:'172/8 (20 ov)', result:'KKR won by 6 runs',
    venue:'Eden Gardens, Kolkata', match:'Match 52', mom:'Sunil Narine (68 off 38)',
    inn1: {
      team:'Kolkata Knight Riders', runs:178, wkts:6, overs:20,
      batting:[
        {name:'Sunil Narine',     out:'c Bairstow b Arshdeep', r:68, b:38, f:6, s:4, sr:178.9},
        {name:'Phil Salt',        out:'b Arshdeep',            r:22, b:16, f:2, s:1, sr:137.5},
        {name:'Angkrish Raghuvanshi',out:'c Shashank b Harshal',r:28, b:20, f:2, s:1, sr:140.0},
        {name:'Rinku Singh',      out:'not out',               r:38, b:22, f:2, s:2, sr:172.7},
        {name:'Andre Russell',    out:'b Harshal',             r:12, b:8,  f:1, s:1, sr:150.0},
      ],
      extras:'Extras: 10 (w:8, nb:2)', total:'178/6 (20 ov)',
      bowling:[
        {name:'Arshdeep Singh',   o:'4',  m:0, r:28, w:2, eco:7.0},
        {name:'Harshal Patel',    o:'4',  m:0, r:38, w:2, eco:9.5},
        {name:'Sam Curran',       o:'4',  m:0, r:35, w:1, eco:8.75},
        {name:'Yuzvendra Chahal', o:'4',  m:0, r:42, w:0, eco:10.5},
        {name:'Shashank Singh',   o:'4',  m:0, r:35, w:1, eco:8.75},
      ]
    },
    inn2: {
      team:'Punjab Kings', runs:172, wkts:8, overs:20,
      batting:[
        {name:'Jonny Bairstow',   out:'c Salt b Narine',       r:52, b:34, f:5, s:2, sr:152.9},
        {name:'Prabhsimran Singh',out:'b Varun',               r:28, b:20, f:2, s:1, sr:140.0},
        {name:'Shashank Singh',   out:'c Russell b Harshit',   r:38, b:26, f:3, s:2, sr:146.2},
        {name:'Sam Curran',       out:'not out',               r:32, b:18, f:2, s:2, sr:177.8},
        {name:'Harshal Patel',    out:'b Narine',              r:8,  b:6,  f:1, s:0, sr:133.3},
      ],
      extras:'Extras: 14 (w:10, nb:4)', total:'172/8 (20 ov)',
      bowling:[
        {name:'Sunil Narine',     o:'4',  m:0, r:22, w:2, eco:5.5},
        {name:'Varun Chakravarthy',o:'4', m:0, r:28, w:2, eco:7.0},
        {name:'Andre Russell',    o:'4',  m:0, r:42, w:1, eco:10.5},
        {name:'Harshit Rana',     o:'4',  m:0, r:38, w:2, eco:9.5},
        {name:'Mitchell Starc',   o:'4',  m:0, r:42, w:1, eco:10.5},
      ]
    }
  },
  {
    date:'28 Apr 2026', t1:'Gujarat Titans', t2:'Lucknow Super Giants',
    s1:'165/7 (20 ov)', s2:'168/4 (19.2 ov)', result:'LSG won by 6 wkts',
    venue:'Narendra Modi Stadium, Ahmedabad', match:'Match 51', mom:'KL Rahul (78* off 48)',
    inn1: {
      team:'Gujarat Titans', runs:165, wkts:7, overs:20,
      batting:[
        {name:'Shubman Gill',     out:'c Rahul b Mohsin',      r:48, b:36, f:4, s:2, sr:133.3},
        {name:'Wriddhiman Saha',  out:'b Ravi Bishnoi',        r:22, b:18, f:2, s:0, sr:122.2},
        {name:'Sai Sudharsan',    out:'c Stoinis b Krunal',    r:35, b:28, f:3, s:1, sr:125.0},
        {name:'David Miller',     out:'not out',               r:38, b:22, f:2, s:2, sr:172.7},
        {name:'Rashid Khan',      out:'b Mohsin',              r:12, b:8,  f:1, s:1, sr:150.0},
      ],
      extras:'Extras: 10 (w:7, nb:3)', total:'165/7 (20 ov)',
      bowling:[
        {name:'Mohsin Khan',      o:'4',  m:0, r:28, w:2, eco:7.0},
        {name:'Ravi Bishnoi',     o:'4',  m:0, r:32, w:2, eco:8.0},
        {name:'Krunal Pandya',    o:'4',  m:0, r:35, w:1, eco:8.75},
        {name:'Marcus Stoinis',   o:'4',  m:0, r:38, w:1, eco:9.5},
        {name:'Yash Thakur',      o:'4',  m:0, r:32, w:1, eco:8.0},
      ]
    },
    inn2: {
      team:'Lucknow Super Giants', runs:168, wkts:4, overs:19.2,
      batting:[
        {name:'KL Rahul',         out:'not out',               r:78, b:48, f:7, s:3, sr:162.5},
        {name:'Quinton de Kock',  out:'c Miller b Rashid',     r:32, b:22, f:3, s:1, sr:145.5},
        {name:'Marcus Stoinis',   out:'c Gill b Noor Ahmad',   r:28, b:18, f:2, s:1, sr:155.6},
        {name:'Deepak Hooda',     out:'b Rashid',              r:18, b:14, f:1, s:1, sr:128.6},
        {name:'Krunal Pandya',    out:'not out',               r:8,  b:4,  f:1, s:0, sr:200.0},
      ],
      extras:'Extras: 4 (w:3, nb:1)', total:'168/4 (19.2 ov)',
      bowling:[
        {name:'Rashid Khan',      o:'4',  m:0, r:22, w:2, eco:5.5},
        {name:'Noor Ahmad',       o:'4',  m:0, r:32, w:1, eco:8.0},
        {name:'Spencer Johnson',  o:'4',  m:0, r:38, w:0, eco:9.5},
        {name:'Sai Kishore',      o:'3.2',m:0, r:28, w:1, eco:8.4},
        {name:'Shubman Gill',     o:'4',  m:0, r:48, w:0, eco:12.0},
      ]
    }
  },
];

const IPL2026_POINTS = [
  // Final league stage standings (after 70 matches, 24 May 2026)
  { pos:1,  team:'Royal Challengers Bengaluru', emoji:'🔴', m:14, w:9, l:5, nr:0, pts:18, nrr:'+0.783' },
  { pos:2,  team:'Gujarat Titans',              emoji:'🔵', m:14, w:9, l:5, nr:0, pts:18, nrr:'+0.652' },
  { pos:3,  team:'Sunrisers Hyderabad',         emoji:'🟠', m:14, w:9, l:5, nr:0, pts:18, nrr:'+0.421' },
  { pos:4,  team:'Rajasthan Royals',            emoji:'🩷', m:14, w:8, l:6, nr:0, pts:16, nrr:'+0.318' },
  { pos:5,  team:'Punjab Kings',                emoji:'🟡', m:14, w:7, l:7, nr:0, pts:14, nrr:'+0.112' },
  { pos:6,  team:'Delhi Capitals',              emoji:'🔵', m:14, w:6, l:8, nr:0, pts:12, nrr:'-0.204' },
  { pos:7,  team:'Chennai Super Kings',         emoji:'🟡', m:14, w:5, l:9, nr:0, pts:10, nrr:'-0.318' },
  { pos:8,  team:'Lucknow Super Giants',        emoji:'🟢', m:14, w:5, l:9, nr:0, pts:10, nrr:'-0.512' },
  { pos:9,  team:'Kolkata Knight Riders',       emoji:'🟣', m:14, w:4, l:10,nr:0, pts:8,  nrr:'-0.634' },
  { pos:10, team:'Mumbai Indians',              emoji:'🔵', m:14, w:3, l:11,nr:0, pts:6,  nrr:'-0.618' },
];

const IPL2026_BATSMEN = [
  // Updated after Qualifier 2 (29 May 2026)
  { pos:1,  name:'Vaibhav Sooryavanshi', team:'RR',  emoji:'🩷', m:16, runs:776, hs:'97',   avg:51.7, sr:198.5, h:0, f:7 },
  { pos:2,  name:'Shubman Gill',         team:'GT',  emoji:'🔵', m:15, runs:722, hs:'104*', avg:52.9, sr:172.4, h:2, f:5 },
  { pos:3,  name:'Sai Sudharsan',        team:'GT',  emoji:'🔵', m:15, runs:712, hs:'98*',  avg:50.9, sr:155.2, h:0, f:6 },
  { pos:4,  name:'Virat Kohli',          team:'RCB', emoji:'🔴', m:15, runs:600, hs:'95',   avg:46.2, sr:152.8, h:0, f:5 },
  { pos:5,  name:'Heinrich Klaasen',     team:'SRH', emoji:'🟠', m:14, runs:594, hs:'89*',  avg:49.5, sr:178.9, h:0, f:6 },
  { pos:6,  name:'Rajat Patidar',        team:'RCB', emoji:'🔴', m:15, runs:582, hs:'93*',  avg:44.8, sr:168.2, h:0, f:5 },
  { pos:7,  name:'Travis Head',          team:'SRH', emoji:'🟠', m:14, runs:548, hs:'102*', avg:43.4, sr:185.4, h:1, f:3 },
  { pos:8,  name:'Jos Buttler',          team:'RR',  emoji:'🩷', m:14, runs:512, hs:'88',   avg:39.4, sr:162.5, h:0, f:4 },
  { pos:9,  name:'Rohit Sharma',         team:'MI',  emoji:'🔵', m:14, runs:498, hs:'98*',  avg:38.3, sr:158.6, h:0, f:4 },
  { pos:10, name:'Devdutt Padikkal',     team:'RCB', emoji:'🔴', m:15, runs:476, hs:'82',   avg:36.6, sr:148.3, h:0, f:4 },
];

// ══════════════════════════════════════════════════════
//  SMART LIVE REFRESH
// ══════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════
//  LIVE SCORE ENGINE
//  Strategy:
//   1. If user has saved a RapidAPI key → use Cricbuzz API (real ball-by-ball)
//   2. Otherwise → poll TOI/NDTV RSS feeds every 60s for score headlines
//  The 2-second interval is removed — RSS feeds don't update that fast
//  and it just hammers the proxy for no benefit.
// ══════════════════════════════════════════════════════

let dashboardRefreshTimer = null;
let liveRefreshTimer      = null;
let espnRefreshTimer      = null;
let lastScoreText         = '';

// ── Cricbuzz RapidAPI live fetch ─────────────────────
async function fetchCricbuzzLive() {
  const key = localStorage.getItem('rapidapi_key');
  if (!key) return false;

  try {
    // Step 1: get list of live matches
    const res = await fetch('https://cricbuzz-cricket.p.rapidapi.com/matches/v1/live', {
      headers: {
        'x-rapidapi-key':  key,
        'x-rapidapi-host': 'cricbuzz-cricket.p.rapidapi.com'
      },
      signal: AbortSignal.timeout(8000)
    });
    if (!res.ok) {
      if (res.status === 403 || res.status === 401) {
        showApiKeyError('⚠️ API Key गलत है या expire हो गई। नई key डालें।');
      }
      return false;
    }

    const data = await res.json();
    // typeMatches → matchValues → matchInfo
    const allMatches = [];
    (data.typeMatches || []).forEach(type => {
      (type.seriesMatches || []).forEach(series => {
        (series.seriesAdWrapper?.matches || []).forEach(m => allMatches.push(m));
      });
    });

    // Find IPL match
    const iplMatch = allMatches.find(m => {
      const desc = (m.matchInfo?.seriesName || '').toLowerCase();
      const t1   = (m.matchInfo?.team1?.teamName || '').toLowerCase();
      const t2   = (m.matchInfo?.team2?.teamName || '').toLowerCase();
      return desc.includes('ipl') || desc.includes('indian premier') ||
             isIPL(t1) || isIPL(t2);
    });

    if (!iplMatch) {
      showNoLiveMatch();
      return true; // key worked, just no IPL match right now
    }

    const info  = iplMatch.matchInfo;
    const score = iplMatch.matchScore;

    // Update team names
    const t1Name = info.team1?.teamName || '';
    const t2Name = info.team2?.teamName || '';
    setEl('lmc-t1', t1Name);
    setEl('lmc-t2', t2Name);
    setEl('lmc-match', `${info.matchDesc || ''} • ${info.startDate ? formatMatchDate(info.startDate) : ''}`);
    setEl('lmc-venue', `📍 ${info.venueInfo?.ground || ''}, ${info.venueInfo?.city || ''}`);

    // Scores
    const inn1 = score?.team1Score?.inngs1;
    const inn2 = score?.team2Score?.inngs1;

    if (inn1) {
      setEl('srh-score', `${inn1.runs}/${inn1.wickets}`);
      setEl('srh-overs', `(${inn1.overs} ov)`);
    } else {
      setEl('srh-score', 'Yet to bat');
      setEl('srh-overs', '');
    }
    if (inn2) {
      setEl('kkr-score', `${inn2.runs}/${inn2.wickets}`);
      setEl('kkr-overs', `(${inn2.overs} ov)`);
    } else {
      setEl('kkr-score', 'Yet to bat');
      setEl('kkr-overs', '');
    }

    // Status
    const statusEl = document.getElementById('lmc-status');
    if (statusEl) {
      statusEl.textContent = info.status || '🔴 LIVE';
      statusEl.style.color = '#f9ca24';
    }

    // Step 2: fetch scorecard for batsmen/bowler
    const matchId = info.matchId;
    if (matchId) await fetchCricbuzzScorecard(matchId, key);

    updateLastUpdated();
    return true;

  } catch(e) {
    console.warn('Cricbuzz API error:', e.message);
    return false;
  }
}

async function fetchCricbuzzScorecard(matchId, key) {
  try {
    const res = await fetch(`https://cricbuzz-cricket.p.rapidapi.com/mcenter/v1/${matchId}/scard`, {
      headers: {
        'x-rapidapi-key':  key,
        'x-rapidapi-host': 'cricbuzz-cricket.p.rapidapi.com'
      },
      signal: AbortSignal.timeout(8000)
    });
    if (!res.ok) return;
    const data = await res.json();

    // Find current innings (last one in scoreCard array)
    const innings = data.scoreCard || [];
    const current = innings[innings.length - 1];
    if (!current) return;

    // Batsmen
    const batsmen = (current.batTeamDetails?.batsmenData || {});
    const activeBats = Object.values(batsmen)
      .filter(b => b.outDesc === '' || b.outDesc === undefined)
      .slice(0, 2);

    const batsmenEl = document.getElementById('live-batsmen');
    if (batsmenEl) {
      if (activeBats.length > 0) {
        batsmenEl.innerHTML = activeBats.map(b => `
          <tr>
            <td style="color:white;text-align:left;font-weight:600">${sanitizeText(b.batName || '')} ${b.isCaptain ? '(c)' : ''} ${b.isKeeper ? '†' : ''}</td>
            <td>${b.runs ?? '—'}</td>
            <td>${b.balls ?? '—'}</td>
            <td>${b.fours ?? 0}</td>
            <td>${b.sixes ?? 0}</td>
            <td>${b.strikeRate ?? '—'}</td>
          </tr>`).join('');
      } else {
        batsmenEl.innerHTML = '<tr><td colspan="6" style="color:#aaa;text-align:center;padding:8px">⏳ डेटा लोड हो रहा है...</td></tr>';
      }
    }

    // Current bowler
    const bowlers = (current.bowlTeamDetails?.bowlersData || {});
    const activeBowler = Object.values(bowlers)
      .filter(b => b.isCurrentBowler)
      .slice(0, 1);

    const bowlerEl = document.getElementById('live-bowler');
    if (bowlerEl) {
      if (activeBowler.length > 0) {
        const b = activeBowler[0];
        bowlerEl.innerHTML = `
          <tr>
            <td style="color:white;text-align:left;font-weight:600">${sanitizeText(b.bowlName || '')}</td>
            <td>${b.overs ?? '—'}</td>
            <td>${b.runs ?? '—'}</td>
            <td>${b.wickets ?? '—'}</td>
            <td>${b.economy ?? '—'}</td>
          </tr>`;
      } else {
        bowlerEl.innerHTML = '<tr><td colspan="5" style="color:#aaa;text-align:center;padding:8px">⏳ गेंदबाज डेटा नहीं मिला</td></tr>';
      }
    }

  } catch(e) {
    console.warn('Scorecard fetch error:', e.message);
  }
}

function formatMatchDate(ts) {
  try {
    return new Date(parseInt(ts)).toLocaleDateString('en-IN', { day:'numeric', month:'short', year:'numeric' });
  } catch { return ''; }
}

function showApiKeyError(msg) {
  const el = document.getElementById('api-save-msg');
  if (el) { el.style.color = '#e74c3c'; el.textContent = msg; }
  document.getElementById('api-setup').style.display = 'block';
}

function showNoLiveMatch() {
  const todayMatches = getTodayMatch();
  const m = todayMatches[0] || IPL2026_SCHEDULE.find(s => s.status === 'upcoming');
  setEl('lmc-status', m ? `⏳ अगला मैच: ${m.date} • ${m.time} IST` : '⏳ अभी कोई लाइव मैच नहीं');
  const batsmenEl = document.getElementById('live-batsmen');
  if (batsmenEl) batsmenEl.innerHTML = '<tr><td colspan="6" style="color:#aaa;text-align:center;padding:12px">⏳ मैच शुरू होने पर स्कोर अपडेट होगा</td></tr>';
  const bowlerEl = document.getElementById('live-bowler');
  if (bowlerEl) bowlerEl.innerHTML = '<tr><td colspan="5" style="color:#aaa;text-align:center;padding:8px">⏳ मैच शुरू होने का इंतजार करें</td></tr>';
}

// ── RSS fallback (no API key) ────────────────────────
async function fetchRSSFallback() {
  const RSS_FEEDS = [
    'https://timesofindia.indiatimes.com/rssfeeds/4719148.cms',
    'https://sports.ndtv.com/feeds/rss/cricket.xml',
  ];

  for (const feed of RSS_FEEDS) {
    try {
      const res = await fetch(
        'https://api.rss2json.com/v1/api.json?rss_url=' + encodeURIComponent(feed),
        { signal: AbortSignal.timeout(7000) }
      );
      if (!res.ok) continue;
      const data = await res.json();
      if (data.status !== 'ok') continue;

      const items = (data.items || []).filter(i => isIPL(i.title || ''));
      if (items.length === 0) continue;

      const latest = items[0];
      const title  = latest.title || '';
      const desc   = (latest.description || '').replace(/<[^>]+>/g, '').trim();

      // Try to extract score from headline e.g. "RCB 145/6 (18.2 ov)"
      const scoreMatch = (title + ' ' + desc).match(/(\d{1,3}\/\d{1,2})\s*\((\d{1,2}\.?\d?)\s*ov/i);

      const statusEl = document.getElementById('lmc-status');
      if (statusEl) {
        statusEl.textContent = scoreMatch
          ? `🏏 ${scoreMatch[1]} (${scoreMatch[2]} ov) — ${sanitizeText(title)}`
          : sanitizeText(title);
        statusEl.style.color = '#f9ca24';
      }

      // Show headline in batsmen row
      const batsmenEl = document.getElementById('live-batsmen');
      if (batsmenEl) {
        batsmenEl.innerHTML = `
          <tr><td colspan="6" style="color:white;text-align:left;padding:8px;font-size:13px">
            📰 ${sanitizeText(title)}
          </td></tr>
          ${desc ? `<tr><td colspan="6" style="color:#aaa;font-size:11px;text-align:left;padding:4px 8px">
            ${sanitizeText(desc.substring(0, 200))}
          </td></tr>` : ''}
          <tr><td colspan="6" style="color:#888;font-size:11px;text-align:center;padding:6px">
            🔑 बेहतर लाइव स्कोर के लिए RapidAPI Key डालें
          </td></tr>`;
      }

      const bowlerEl = document.getElementById('live-bowler');
      if (bowlerEl) bowlerEl.innerHTML = '<tr><td colspan="5" style="color:#aaa;text-align:center;padding:8px;font-size:12px">RSS फीड से बॉलर डेटा उपलब्ध नहीं</td></tr>';

      updateLastUpdated();
      return; // success
    } catch(e) { continue; }
  }

  // All feeds failed
  showNoLiveMatch();
}

// ── Main refresh dispatcher ──────────────────────────
async function refreshLiveScore() {
  const btn = document.querySelector('.lmc-refresh-btn');
  if (btn) { btn.textContent = '⏳'; btn.disabled = true; }

  try {
    const key = localStorage.getItem('rapidapi_key');
    if (key) {
      // Try Cricbuzz API first
      const ok = await fetchCricbuzzLive();
      if (!ok) await fetchRSSFallback(); // fall back if API fails
    } else {
      await fetchRSSFallback();
    }
  } finally {
    if (btn) { btn.textContent = '🔄'; btn.disabled = false; }
  }
}

function updateLastUpdated() {
  const time = new Date().toLocaleTimeString('hi-IN');
  const lu  = document.getElementById('last-updated');
  const lu2 = document.getElementById('ipl-last-updated');
  if (lu)  lu.textContent  = 'अपडेट: ' + time;
  if (lu2) lu2.textContent = 'अपडेट: ' + time;
}

// ── Today's match header ─────────────────────────────
function getTodayMatch() {
  const today = new Date();
  const dd = today.getDate();
  const MONTHS = ['January','February','March','April','May','June',
                  'July','August','September','October','November','December'];
  const mm  = MONTHS[today.getMonth()];
  const yy  = today.getFullYear();
  const todayStr = `${dd} ${mm} ${yy}`;
  return IPL2026_SCHEDULE.filter(m => m.date === todayStr);
}

function updateLiveMatchHeader() {
  const matches = getTodayMatch();
  const m = matches.length > 0 ? matches[0] : IPL2026_SCHEDULE.find(s => s.status === 'upcoming');
  if (!m) return;
  setEl('lmc-match',  `${m.match} • ${m.date} • ${m.time} IST`);
  setEl('lmc-t1',     m.t1);
  setEl('lmc-t2',     m.t2);
  setEl('lmc-venue',  `📍 ${m.venue}`);
  setEl('lmc-status', matches.length > 0
    ? `⏳ मैच ${m.time} IST पर शुरू होगा`
    : `⏳ अगला मैच: ${m.date} • ${m.time} IST`);
  const commTitle = document.getElementById('comm-modal-match-title');
  if (commTitle) commTitle.textContent = `${m.t1} vs ${m.t2} • ${m.match} • ${m.date}`;
  window._todayT1 = m.t1.toLowerCase();
  window._todayT2 = m.t2.toLowerCase();
}

// Helper
function setEl(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

// ── Timers ───────────────────────────────────────────
function startDashboardRefresh() {
  updateLiveMatchHeader();
  refreshLiveScore();
  // If API key present: refresh every 30s (Cricbuzz updates ~every 30s)
  // If no key: refresh every 60s (RSS feeds don't update faster)
  const interval = localStorage.getItem('rapidapi_key') ? 30000 : 60000;
  dashboardRefreshTimer = setInterval(refreshLiveScore, interval);
}

function startLiveRefresh() {
  clearInterval(liveRefreshTimer);
  clearInterval(espnRefreshTimer);
  // Fetch ESPN/TOI feed for the news panel — every 60s is plenty
  espnRefreshTimer = setInterval(fetchLiveFromESPN, 60000);
}

function openCommentary() {
  document.getElementById('comm-modal').style.display = 'block';
  document.body.style.overflow = 'hidden';
  loadCommentary();
  if (!window._commModalTimer) {
    window._commModalTimer = setInterval(loadCommentary, 10000);
  }
}

function closeCommentary() {
  document.getElementById('comm-modal').style.display = 'none';
  document.body.style.overflow = '';
  clearInterval(window._commModalTimer);
  window._commModalTimer = null;
}

async function loadCommentary() {
  const feedEl  = document.getElementById('comm-modal-feed');
  const statusEl = document.getElementById('comm-status');
  if (statusEl) statusEl.textContent = '⏳ अपडेट हो रहा है...';

  try {
    const res = await fetch(
      'https://api.rss2json.com/v1/api.json?rss_url=' +
      encodeURIComponent('https://timesofindia.indiatimes.com/rssfeeds/4719148.cms'),
      { signal: AbortSignal.timeout(6000) }
    );
    const data = await res.json();
    const items = (data.items || []).filter(i => isIPL(i.title || ''));

    if (feedEl) {
      feedEl.innerHTML = items.length === 0
        ? '<div style="color:#aaa;padding:10px">⏳ अभी कोई लाइव अपडेट नहीं — मैच शुरू होने पर कमेंट्री आएगी</div>'
        : items.map(i => {
            // Fix: sanitize all RSS content before injecting into innerHTML
            const t    = sanitizeText(i.title || '');
            const desc = sanitizeText((i.description || '').replace(/<[^>]+>/g, ''));
            const link = sanitizeUrl(i.link || '#');
            const pub  = i.pubDate ? new Date(i.pubDate).toLocaleTimeString('hi-IN', {hour:'2-digit', minute:'2-digit'}) : '';
            const isSRHKKR = /(srh|kkr|sunrisers|kolkata)/i.test(i.title || '');
            const cls  = isSRHKKR ? 'six' : '';
            return `<div class="ball-item ${cls}" style="cursor:pointer;margin-bottom:8px" onclick="window.open('${link}','_blank','noopener,noreferrer')">
              <span class="ball-badge">${isSRHKKR ? '🔴' : '📰'}</span>
              <span>
                <strong>${pub}</strong> ${t}
                ${desc ? `<br><small style="color:#888">${desc.substring(0,120)}...</small>` : ''}
              </span>
            </div>`;
          }).join('');
    }

    if (statusEl) statusEl.textContent = '✅ अपडेट: ' + new Date().toLocaleTimeString('hi-IN') + ' • अगला अपडेट 10 सेकंड में';

  } catch(e) {
    if (statusEl) statusEl.textContent = '⚠️ लोड नहीं हुआ';
  }
}

// ══════════════════════════════════════════════════════
//  ESPN / TOI RSS — IPL NEWS FEED PANEL
// ══════════════════════════════════════════════════════

async function fetchESPN() {
  const RSS2JSON = 'https://api.rss2json.com/v1/api.json?rss_url=';
  const FEEDS = [
    'https://timesofindia.indiatimes.com/rssfeeds/4719148.cms',
    'https://sports.ndtv.com/feeds/rss/cricket.xml',
  ];
  for (const feed of FEEDS) {
    try {
      const res = await fetch(RSS2JSON + encodeURIComponent(feed),
        { signal: AbortSignal.timeout(8000) });
      if (!res.ok) continue;
      const data = await res.json();
      if (data.status === 'ok' && data.items?.length > 0) return data.items;
    } catch(e) { continue; }
  }
  return [];
}

const IPL_KEYWORDS = ['ipl','indian premier','srh','kkr','gt','pbks','mi','csk','rcb','dc','rr','lsg',
  'sunrisers','kolkata','gujarat','punjab','mumbai','chennai','bangalore','bengaluru',
  'delhi','rajasthan','lucknow','hyderabad'];

function isIPL(text) {
  const t = text.toLowerCase();
  return IPL_KEYWORDS.some(k => t.includes(k));
}

function extractScore(text) {
  // Match patterns like "SRH 145/6 (18.2 ov)" or "KKR need 45 runs"
  const m = text.match(/(\d+\/\d+)\s*\((\d+\.?\d*)\s*ov/i);
  return m ? `${m[1]} (${m[2]} ov)` : null;
}

async function fetchLiveFromESPN() {
  const btn = document.querySelector('.refresh-btn');
  if (btn) { btn.textContent = '⏳'; btn.disabled = true; }

  try {
    const items = await fetchESPN();
    // items can be rss2json objects {title,description,link,pubDate}
    // or DOM elements from allorigins fallback
    const getField = (item, field) => {
      if (typeof item.querySelector === 'function')
        return item.querySelector(field)?.textContent || '';
      return item[field] || '';
    };

    const iplItems = items.filter(i =>
      isIPL(getField(i,'title')) || isIPL(getField(i,'description'))
    );

    const feedEl = document.getElementById('espn-feed-list');
    if (!feedEl) return;

    if (iplItems.length === 0) {
      feedEl.innerHTML = `<div class="espn-item">
        <div class="espn-title">📡 ESPN से कोई IPL अपडेट नहीं मिला — रिफ्रेश करें</div>
      </div>`;
    } else {
      // Update today match score cards
      iplItems.forEach(item => {
        const title = getField(item, 'title');
        const desc  = getField(item, 'description').replace(/<[^>]+>/g, '');
        const tl    = title.toLowerCase();

        if ((tl.includes('srh') || tl.includes('sunrisers')) &&
            (tl.includes('kkr') || tl.includes('kolkata'))) {
          const el = document.getElementById('score-srh-kkr');
          if (el) { el.textContent = title; el.style.color = '#f9ca24'; }
        }
        if ((tl.includes('gt') || tl.includes('gujarat')) &&
            (tl.includes('pbks') || tl.includes('punjab'))) {
          const el = document.getElementById('score-gt-pbks');
          if (el) { el.textContent = title; el.style.color = '#f9ca24'; }
        }
      });

      // Render feed
      feedEl.innerHTML = iplItems.slice(0, 12).map(item => {
        const title = sanitizeText(getField(item, 'title'));
        const link  = sanitizeUrl(getField(item, 'link'));
        const pub   = getField(item, 'pubDate');
        const desc  = sanitizeText(getField(item, 'description').replace(/<[^>]+>/g, '').substring(0, 150));
        const time  = pub ? new Date(pub).toLocaleString('en-IN',
          { day:'numeric', month:'short', hour:'2-digit', minute:'2-digit' }) : '';
        const score   = extractScore(getField(item, 'title') + ' ' + getField(item, 'description'));
        const isMatch = getField(item, 'title').toLowerCase().includes('win') ||
                        getField(item, 'title').toLowerCase().includes('beat') ||
                        getField(item, 'title').toLowerCase().includes('star') ||
                        score !== null;
        return `<div class="espn-item${isMatch ? ' live-score' : ''}" onclick="window.open('${link}','_blank','noopener,noreferrer')">
          <div class="espn-time">${time}</div>
          <div class="espn-title">${title}</div>
          ${score ? `<div class="espn-score">🏏 ${sanitizeText(score)}</div>` : ''}
          ${desc ? `<div style="font-size:12px;color:#666;margin-top:3px">${desc}...</div>` : ''}
        </div>`;
      }).join('');

      // Update breaking ticker with IPL headlines
      const ticker = document.querySelector('.ticker span');
      if (ticker) {
        ticker.innerHTML = iplItems.slice(0, 5)
          .map(i => sanitizeText(getField(i, 'title'))).filter(Boolean)
          .join(' &nbsp;|&nbsp; ');
      }
    }
  } catch(e) {
    console.warn('ESPN error:', e.message);
  } finally {
    if (btn) { btn.textContent = '🔄 रिफ्रेश'; btn.disabled = false; }
    const lu = document.getElementById('last-updated');
    if (lu) lu.textContent = 'ESPN: ' + new Date().toLocaleTimeString('hi-IN');
    const lu2 = document.getElementById('ipl-last-updated');
    if (lu2) lu2.textContent = 'ESPN: ' + new Date().toLocaleTimeString('hi-IN');
  }
}

// ══════════════════════════════════════════════════════
//  RENDER STATIC DATA
// ══════════════════════════════════════════════════════

function renderSchedule() {
  const grid = document.getElementById('ipl-schedule-grid');
  if (!grid) return;
  grid.innerHTML = IPL2026_SCHEDULE.map(m => {
    const isToday = m.status === 'today';
    return `<div class="schedule-card ${isToday ? 'today-match' : 'upcoming'}">
      <div class="sch-date">📅 ${m.date} • ${m.time} IST</div>
      <div class="sch-teams">
        <span class="sch-team">${m.t1}</span>
        <span class="sch-vs">VS</span>
        <span class="sch-team">${m.t2}</span>
      </div>
      <div class="sch-venue">📍 ${m.venue} • ${m.match}</div>
      ${isToday
        ? '<span class="sch-badge" style="background:#e74c3c;color:white">🔴 आज का मैच</span>'
        : '<span class="sch-badge upcoming-badge">⏳ आने वाला</span>'}
    </div>`;
  }).join('');
}

function renderResults() {
  const grid = document.getElementById('recent-results-grid');
  if (!grid) return;
  grid.innerHTML = IPL2026_RESULTS.map((m, idx) => `
    <div class="schedule-card" style="border-left:4px solid #27ae60">
      <div class="sch-date">📅 ${m.date} • ${m.match}</div>
      <div class="sch-teams">
        <span class="sch-team">${m.t1}</span><span class="sch-vs">VS</span><span class="sch-team">${m.t2}</span>
      </div>
      <div style="font-size:13px;margin:6px 0;line-height:1.9">
        <div>🏏 ${m.t1}: <strong>${m.s1}</strong></div>
        <div>🏏 ${m.t2}: <strong>${m.s2}</strong></div>
      </div>
      <div class="sch-venue">📍 ${m.venue}</div>
      <div style="font-size:13px;color:#27ae60;font-weight:bold;margin-top:6px">🏆 ${m.result}</div>
      <div style="font-size:12px;color:#888;margin-top:3px">⭐ MOM: ${m.mom}</div>
      <button class="scorecard-btn" onclick="openScorecard(${idx})">📋 Full Scorecard देखें</button>
    </div>`).join('');
}

// ── Scorecard Modal ──────────────────────────────────
function openScorecard(idx) {
  const m = IPL2026_RESULTS[idx];
  const modal = document.getElementById('scorecard-modal');
  const body  = document.getElementById('scorecard-modal-body');

  function inningsHTML(inn) {
    const batRows = inn.batting.map(b =>
      `<tr><td>${b.name}</td><td style="color:#888;font-size:12px">${b.out}</td>
       <td><strong>${b.r}</strong></td><td>${b.b}</td><td>${b.f}</td><td>${b.s}</td><td>${b.sr}</td></tr>`
    ).join('');
    const bowlRows = inn.bowling.map(b =>
      `<tr><td>${b.name}</td><td>${b.o}</td><td>${b.m}</td><td>${b.r}</td><td><strong>${b.w}</strong></td><td>${b.eco}</td></tr>`
    ).join('');
    return `
      <h4 style="color:#6c3483;margin:14px 0 8px">🏏 Batting — ${inn.team}</h4>
      <div class="table-wrap">
        <table class="scorecard-table">
          <thead><tr><th>Batsman</th><th>Dismissal</th><th>R</th><th>B</th><th>4s</th><th>6s</th><th>SR</th></tr></thead>
          <tbody>${batRows}</tbody>
        </table>
      </div>
      <div style="font-size:12px;color:#888;margin:4px 0 10px">${inn.extras} &nbsp;|&nbsp; <strong>Total: ${inn.total}</strong></div>
      <h4 style="color:#6c3483;margin:10px 0 8px">🎯 Bowling</h4>
      <div class="table-wrap">
        <table class="scorecard-table">
          <thead><tr><th>Bowler</th><th>O</th><th>M</th><th>R</th><th>W</th><th>Eco</th></tr></thead>
          <tbody>${bowlRows}</tbody>
        </table>
      </div>`;
  }

  body.innerHTML = `
    <div style="margin-bottom:14px">
      <div style="font-size:18px;font-weight:bold;color:#1a1a2e">${m.t1} vs ${m.t2}</div>
      <div style="font-size:13px;color:#888">📅 ${m.date} • ${m.match} • 📍 ${m.venue}</div>
      <div style="margin-top:8px;display:flex;gap:16px;flex-wrap:wrap">
        <div style="background:#f0e6ff;padding:8px 14px;border-radius:8px;font-size:13px">
          🏏 ${m.t1}: <strong>${m.s1}</strong>
        </div>
        <div style="background:#eafaf1;padding:8px 14px;border-radius:8px;font-size:13px">
          🏏 ${m.t2}: <strong>${m.s2}</strong>
        </div>
      </div>
      <div style="margin-top:8px;font-size:14px;font-weight:bold;color:#27ae60">🏆 ${m.result}</div>
      <div style="font-size:13px;color:#888">⭐ Player of the Match: <strong>${m.mom}</strong></div>
    </div>
    <hr style="border:1px solid #eee;margin:12px 0">
    ${inningsHTML(m.inn1)}
    <hr style="border:1px solid #eee;margin:12px 0">
    ${inningsHTML(m.inn2)}`;

  modal.style.display = 'flex';
}

function closeScorecard() {
  document.getElementById('scorecard-modal').style.display = 'none';
}

function renderPoints() {
  const tbody = document.getElementById('points-tbody') ||
                document.querySelector('#sec-points .table-wrap table tbody');
  if (!tbody) return;
  tbody.innerHTML = IPL2026_POINTS.map(t => `
    <tr class="${t.pos <= 4 ? 'qualify' : ''}">
      <td>${t.pos}</td><td>${t.emoji} ${t.team}</td>
      <td>${t.m}</td><td>${t.w}</td><td>${t.l}</td><td>${t.nr}</td>
      <td><strong>${t.pts}</strong></td><td>${t.nrr}</td>
    </tr>`).join('');
}

function renderBatsmen() {
  const tbody = document.getElementById('top-batsmen-body');
  if (!tbody) return;
  tbody.innerHTML = IPL2026_BATSMEN.map(p => `
    <tr>
      <td>${p.pos}</td><td>${p.emoji} ${p.name}</td><td>${p.team}</td><td>${p.m}</td>
      <td><strong>${p.runs}</strong></td><td>${p.hs}</td><td>${p.avg}</td><td>${p.sr}</td>
      <td>${p.h}</td><td>${p.f}</td>
    </tr>`).join('');
}

// ══════════════════════════════════════════════════════
//  TAB SWITCHING
// ══════════════════════════════════════════════════════

function switchSection(name, btn) {
  document.querySelectorAll('.sec-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.sec-panel').forEach(p => p.classList.add('hidden'));
  document.getElementById('sec-' + name).classList.remove('hidden');
}

function switchInnings(id, btn) {
  document.querySelectorAll('.sc-tab').forEach(t => t.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.querySelectorAll('.scorecard').forEach(s => s.classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
}

function showComm(idx, btn) {
  document.querySelectorAll('.comm-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  // Fix: only target commentary list divs, not the modal (which also starts with "comm-")
  document.querySelectorAll('.commentary-list[id^="comm-"]').forEach(c => c.classList.add('hidden'));
  document.getElementById('comm-' + idx).classList.remove('hidden');
}

// ══════════════════════════════════════════════════════
//  API KEY BOX
// ══════════════════════════════════════════════════════

function showApiBox() {
  const box = document.getElementById('api-setup');
  box.style.display = (box.style.display === 'none' || !box.style.display) ? 'block' : 'none';
}

function saveApiKey() {
  const key = document.getElementById('api-key-input').value.trim();
  const msg = document.getElementById('api-save-msg');
  if (!key) { msg.style.color = '#e74c3c'; msg.textContent = '⚠️ Key डालें।'; return; }
  localStorage.setItem('rapidapi_key', key);
  msg.style.color = '#27ae60';
  msg.textContent = '✅ Key सेव हो गई! अब Cricbuzz से लाइव डेटा मिलेगा।';
  // Restart refresh with faster 30s interval now that we have a key
  clearInterval(dashboardRefreshTimer);
  dashboardRefreshTimer = setInterval(refreshLiveScore, 30000);
  refreshLiveScore(); // immediate fetch with new key
  setTimeout(() => { document.getElementById('api-setup').style.display = 'none'; }, 1500);
}

// ══════════════════════════════════════════════════════
//  PAGE LOAD
// ══════════════════════════════════════════════════════

window.addEventListener('DOMContentLoaded', () => {
  // 1. Render all static data immediately
  renderSchedule();
  renderResults();
  renderPoints();
  renderBatsmen();
  // Load news from JSON
  loadNewsFromJSON();

  // 2. DateTime
  updateDateTime();
  setInterval(updateDateTime, 60000);

  // 3. Restore API key
  const savedKey = localStorage.getItem('rapidapi_key');
  if (savedKey) {
    document.getElementById('api-key-input').value = savedKey;
    document.getElementById('api-setup').style.display = 'none';
  }

  // 4. Fetch ESPN/TOI live data
  fetchLiveFromESPN();
  startLiveRefresh();
  startDashboardRefresh();

  // 5. Newsletter — replace alert with inline confirmation
  document.querySelector('.newsletter button').addEventListener('click', () => {
    const input = document.querySelector('.newsletter input');
    const btn   = document.querySelector('.newsletter button');
    if (input.value.includes('@')) {
      btn.textContent = '✅ सब्सक्राइब!';
      btn.style.background = '#27ae60';
      btn.disabled = true;
      input.value = '';
      setTimeout(() => {
        btn.textContent = 'सब्सक्राइब';
        btn.style.background = '';
        btn.disabled = false;
      }, 3000);
    } else {
      input.style.border = '2px solid #e74c3c';
      input.placeholder = '⚠️ वैध ईमेल डालें';
      setTimeout(() => {
        input.style.border = '';
        input.placeholder = 'आपका ईमेल';
      }, 2000);
    }
  });

  // 6. Fix: wire up search input with addEventListener instead of inline oninput
  const searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.addEventListener('input', () => searchNews(searchInput.value));
  }

  // 7. Init poll state from localStorage
  initPoll();

  // 8. Keyboard: close modals with Escape key
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      closeScorecard();
      closeCommentary();
    }
  });
});

function updateDateTime() {
  const opts = { weekday:'long', year:'numeric', month:'long', day:'numeric', hour:'2-digit', minute:'2-digit' };
  document.getElementById('datetime').textContent = new Date().toLocaleDateString('hi-IN', opts);
}

// ══════════════════════════════════════════════════════
//  LOAD NEWS FROM news.json — with pagination & error state
// ══════════════════════════════════════════════════════

const CAT_LABELS = {
  rashtriya:  { label: 'राष्ट्रीय',   cls: '' },
  rajniti:    { label: 'राजनीति',   cls: 'red' },
  khel:       { label: 'खेल',       cls: 'green' },
  manoranjan: { label: 'मनोरंजन', cls: 'orange' },
  technology: { label: 'तकनीक',    cls: 'purple' },
  business:   { label: 'व्यापार',   cls: 'yellow' },
};

let allNews = [];
let newsPage = 1;
const NEWS_PER_PAGE = 6;

async function loadNewsFromJSON() {
  try {
    const res = await fetch('news.json?t=' + Date.now());
    if (!res.ok) throw new Error('HTTP ' + res.status);
    allNews = await res.json();
    const grid = document.getElementById('news-grid');
    if (!grid || !allNews.length) return;
    newsPage = 1;
    renderNewsPage();
  } catch(e) {
    console.warn('news.json load failed:', e.message);
    const grid = document.getElementById('news-grid');
    if (grid) {
      grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:40px;color:#888">
        ⚠️ समाचार लोड नहीं हो सके। कृपया पेज रिफ्रेश करें।
      </div>`;
    }
    const btn = document.getElementById('load-more-btn');
    if (btn) btn.style.display = 'none';
  }
}

function renderNewsPage() {
  const grid = document.getElementById('news-grid');
  if (!grid) return;
  const end     = newsPage * NEWS_PER_PAGE;
  const visible = allNews.slice(0, end);

  grid.innerHTML = visible.map(n => {
    const cat = CAT_LABELS[n.category] || { label: n.category, cls: '' };
    return `
      <article class="news-card" data-cat="${n.category}">
        <img src="${n.image}" alt="${sanitizeText(n.title)}" loading="lazy"
             onerror="this.src='https://picsum.photos/seed/${n.category}/400/220'"/>
        <div class="card-body">
          <span class="category-tag ${cat.cls}">${cat.label}</span>
          <h3>${sanitizeText(n.title)}</h3>
          <p>${sanitizeText(n.description)}</p>
          <div class="card-footer">
            <span>✍️ ${sanitizeText(n.author)}</span>
            <span>⏰ ${sanitizeText(n.time)}</span>
          </div>
        </div>
      </article>`;
  }).join('');

  // Show/hide Load More button
  const btn = document.getElementById('load-more-btn');
  if (btn) btn.style.display = end >= allNews.length ? 'none' : 'inline-block';
}

// Real pagination — replaces the old alert() stub
function loadMoreNews() {
  newsPage++;
  renderNewsPage();
}

function filterNews(cat, btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.news-card').forEach(card =>
    card.classList.toggle('hidden', cat !== 'all' && card.dataset.cat !== cat));
}

function searchNews(query) {
  const q = query.trim().toLowerCase();
  let count = 0;
  document.querySelectorAll('.news-card').forEach(card => {
    const match = !q || card.innerText.toLowerCase().includes(q);
    card.classList.toggle('hidden', !match);
    if (match) count++;
  });
  document.getElementById('search-result-info').textContent =
    q ? `"${query}" के लिए ${count} समाचार मिले` : '';
}

function clearSearch() {
  document.getElementById('searchInput').value = '';
  searchNews('');
}

// ══════════════════════════════════════════════════════
//  WEATHER
// ══════════════════════════════════════════════════════

const weatherData = {
  delhi:     { icon:'☀️',  temp:'38°C', desc:'साफ आसमान',        city:'नई दिल्ली', humidity:'45%', wind:'12 km/h', vis:'10 km', feels:'41°C' },
  mumbai:    { icon:'🌦️', temp:'32°C', desc:'हल्की बारिश',       city:'मुंबई',     humidity:'82%', wind:'18 km/h', vis:'6 km',  feels:'36°C' },
  bangalore: { icon:'⛅',  temp:'26°C', desc:'आंशिक बादल',       city:'बेंगलुरु',  humidity:'60%', wind:'10 km/h', vis:'12 km', feels:'27°C' },
  kolkata:   { icon:'🌩️', temp:'34°C', desc:'गरज के साथ बारिश', city:'कोलकाता',   humidity:'75%', wind:'22 km/h', vis:'5 km',  feels:'39°C' },
};

function showWeather(city, btn) {
  document.querySelectorAll('.city-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const d = weatherData[city];
  ['w-icon','w-temp','w-desc','w-city','w-humidity','w-wind','w-vis','w-feels']
    .forEach((id, i) => document.getElementById(id).textContent =
      [d.icon, d.temp, d.desc, d.city, d.humidity, d.wind, d.vis, d.feels][i]);
}

// ══════════════════════════════════════════════════════
//  POLL — with localStorage persistence
// ══════════════════════════════════════════════════════

// Fix: load saved votes from localStorage, fall back to defaults
const DEFAULT_VOTES = [120, 95, 60, 45];
const pollVotes = JSON.parse(localStorage.getItem('poll_votes') || 'null') || [...DEFAULT_VOTES];

function vote(index) {
  // Prevent double-voting
  if (localStorage.getItem('poll_voted')) {
    document.getElementById('poll-options').classList.add('hidden');
    document.getElementById('poll-results').classList.remove('hidden');
    renderPollResults();
    return;
  }
  pollVotes[index]++;
  localStorage.setItem('poll_votes', JSON.stringify(pollVotes));
  localStorage.setItem('poll_voted', '1');
  document.getElementById('poll-options').classList.add('hidden');
  document.getElementById('poll-results').classList.remove('hidden');
  renderPollResults();
}

function renderPollResults() {
  const total = pollVotes.reduce((a, b) => a + b, 0);
  pollVotes.forEach((v, i) => {
    const pct = Math.round((v / total) * 100);
    document.getElementById(`bar-${i}`).style.width = pct + '%';
    document.getElementById(`pct-${i}`).textContent = pct + '%';
  });
  document.getElementById('poll-total').textContent = `कुल ${total} वोट`;
}

// On load: if already voted, show results
function initPoll() {
  if (localStorage.getItem('poll_voted')) {
    document.getElementById('poll-options').classList.add('hidden');
    document.getElementById('poll-results').classList.remove('hidden');
    renderPollResults();
  }
}
