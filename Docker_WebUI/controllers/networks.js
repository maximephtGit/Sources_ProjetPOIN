import { docker } from '../server.js';


export const Networks = async function(req, res) {


    let container_networks = [];
    // List all containers
    let container = await docker.listContainer({ all: true });
    for (let i = 0; i < container.length; i++) {
        let network_name = container[i].HostConfig.NetworkMode;
        try { container_networks.push(container[i].NetworkSettings.Networks[network_name].NetworkID) } catch {}
    }


    let networks = await docker.listNetworks({ all: true });

    let network_list = `
        <thead>
            <tr>
                <th class="w-1"><input class="form-check-input m-0 align-middle" name="select" type="checkbox" aria-label="Select all" onclick="selectAll()"></th>
                <th><label class="table-sort" data-sort="sort-name">Name</label></th>
                <th><label class="table-sort" data-sort="sort-city">ID</label></th>
                <th><label class="table-sort" data-sort="sort-score">Status</label></th>
                <th><label class="table-sort" data-sort="sort-date">Created</label></th>
                <th><label class="table-sort" data-sort="sort-progress">Action</label></th>
            </tr>
        </thead>
        <tbody class="table-tbody">`


    for (let i = 0; i < networks.length; i++) {

        // let date = new Date(images[i].Created * 1000);
        // let created = date.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
        
        let status = '';
        if (container_networks.includes(networks[i].Id)) {
            status = `In use`;
        }

        let details = `
            <tr>
                <td><input class="form-check-input m-0 align-middle" name="select" value="${networks[i].Id}" type="checkbox" aria-label="Select"></td>
                <td class="sort-name">${networks[i].Name}</td>
                <td class="sort-city">${networks[i].Id}</td>
                <td class="sort-score text-green">${status}</td>
                <td class="sort-date" data-date="1628122643">${networks[i].Created}</td>
                <td class="text-end"><a class="btn" href="#">Details</a></td>
            </tr>`
            network_list += details;
    }
    
    network_list += `</tbody>`

    res.render("networks", {
        name: req.session.user,
        role: req.session.role,
        avatar: req.session.user.charAt(0).toUpperCase(),
        network_list: network_list,
        network_count: networks.length,
        alert: '',
    });
}




export const removeNetwork = async function(req, res) {
    let networks = req.body.select;

    if (typeof(networks) == 'string') {
        networks = [networks];
    }

    for (let i = 0; i < networks.length; i++) {
        
        if (networks[i] != 'on') {
            try {
                console.log(`Removing network: ${networks[i]}`);
                let network = docker.getNetwork(networks[i]);
                await network.remove();
            } catch (error) {
                console.log(`Unable to remove network: ${networks[i]}`);
            }
        }
    }
    res.redirect("/networks");
}